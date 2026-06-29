"""MITRE ATT&CK technique validation.

The LLM is asked for ATT&CK technique ids, but model-supplied ids can be
malformed or hallucinated. To guarantee we only ever stamp a *real* technique
id onto an attack-pattern (the merge key OpenCTI uses against its ATT&CK
dataset), we validate against the official ATT&CK STIX catalog.

The catalog is downloaded once from MITRE's public repo and cached locally.
When the catalog is unavailable (offline / download skipped) we fall back to
strict format validation only.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx

# Technique ids look like T1566 or T1566.001 (sub-technique).
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Official ATT&CK STIX data, by domain.
_DOMAIN_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}


def normalize_id(raw: str | None) -> str | None:
    """Uppercase/trim a candidate id and return it only if well-formed."""
    if not raw:
        return None
    candidate = raw.strip().upper()
    return candidate if TECHNIQUE_ID_RE.match(candidate) else None


def _cache_path() -> Path:
    base = (
        os.getenv("LOCALAPPDATA")
        or os.getenv("XDG_CACHE_HOME")
        or str(Path.home() / ".cache")
    )
    d = Path(base) / "ai-stix-mapper"
    d.mkdir(parents=True, exist_ok=True)
    return d / "attack-index.json"


class AttackIndex:
    """Lookup of valid technique ids and their canonical names."""

    def __init__(self, id_to_name: dict[str, str]):
        self.id_to_name = id_to_name
        self._name_to_id = {name.lower(): tid for tid, name in id_to_name.items()}

    def has_id(self, tid: str) -> bool:
        return tid in self.id_to_name

    def canonical_name(self, tid: str) -> str | None:
        return self.id_to_name.get(tid)

    def id_for_name(self, name: str) -> str | None:
        return self._name_to_id.get(name.strip().lower())

    # ------------------------------------------------------------------

    @classmethod
    def load(
        cls,
        domains: tuple[str, ...] = ("enterprise", "mobile", "ics"),
        allow_download: bool = True,
        refresh: bool = False,
    ) -> "AttackIndex | None":
        """Load the index from cache, downloading once if needed.

        Returns None if the catalog isn't cached and can't be downloaded.
        """
        cache = _cache_path()
        if cache.exists() and not refresh:
            try:
                return cls(json.loads(cache.read_text(encoding="utf-8")))
            except (ValueError, OSError):
                pass  # corrupt cache -> rebuild below
        if not allow_download:
            return None

        id_to_name: dict[str, str] = {}
        for domain in domains:
            url = _DOMAIN_URLS.get(domain)
            if not url:
                continue
            id_to_name.update(_fetch_domain(url))
        if not id_to_name:
            return None
        cache.write_text(json.dumps(id_to_name), encoding="utf-8")
        return cls(id_to_name)


def _fetch_domain(url: str) -> dict[str, str]:
    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        resp = client.get(url)
        resp.raise_for_status()
        bundle = resp.json()
    return _parse_bundle(bundle)


def _parse_bundle(bundle: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                ext_id = ref["external_id"]
                break
        if ext_id and TECHNIQUE_ID_RE.match(ext_id) and obj.get("name"):
            out[ext_id] = obj["name"]
    return out


def resolve_technique(
    name: str, raw_id: str | None, index: "AttackIndex | None"
) -> tuple[str, str | None]:
    """Resolve an attack-pattern to (name, verified_external_id).

    Guarantees the returned id is either a real technique id or None — never a
    malformed or fabricated one.

    - With a catalog: confirm the id; if it's wrong/missing, recover it from the
      technique name; normalize the name to ATT&CK's canonical spelling.
    - Without a catalog: keep the id only if it is well-formed.
    """
    tid = normalize_id(raw_id)

    if index is None:
        return name, tid

    if tid and index.has_id(tid):
        return index.canonical_name(tid) or name, tid

    # id was absent, malformed, or not a real technique -> try the name.
    recovered = index.id_for_name(name)
    if recovered:
        return index.canonical_name(recovered) or name, recovered
    return name, None
