"""Build a STIX 2.1 bundle from an Extraction.

Design choices:
- No observed-data objects are ever created. IOCs become an Indicator plus a
  cyber-observable (SCO), linked with a `based-on` relationship.
- Every object is stamped with created_by_ref pointing at an author Identity.
- A Report SDO ties the whole graph together via object_refs, which is what
  OpenCTI ingests as a container.
"""

from __future__ import annotations

from datetime import datetime, timezone

import stix2

from .attack import AttackIndex, resolve_technique
from .schema import Entity, Extraction, Indicator

# Map our SDO type strings to stix2 classes.
_ENTITY_CLASSES = {
    "attack-pattern": stix2.AttackPattern,
    "campaign": stix2.Campaign,
    "course-of-action": stix2.CourseOfAction,
    "identity": stix2.Identity,
    "infrastructure": stix2.Infrastructure,
    "intrusion-set": stix2.IntrusionSet,
    "location": stix2.Location,
    "malware": stix2.Malware,
    "threat-actor": stix2.ThreatActor,
    "tool": stix2.Tool,
    "vulnerability": stix2.Vulnerability,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ioc_type -> OpenCTI "main observable type" label. OpenCTI can infer this from
# the pattern, but stamping it explicitly makes indicator import deterministic.
_OCTI_OBSERVABLE_TYPE = {
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "domain-name": "Domain-Name",
    "url": "Url",
    "email-addr": "Email-Addr",
    "file:md5": "StixFile",
    "file:sha1": "StixFile",
    "file:sha256": "StixFile",
}


def _build_observable(ioc: Indicator) -> tuple[stix2.base._STIXBase, str, str]:
    """Return (sco_object, stix_pattern, opencti_main_observable_type)."""
    t = ioc.ioc_type
    v = ioc.value
    octi = _OCTI_OBSERVABLE_TYPE[t]
    if t == "ipv4-addr":
        return stix2.IPv4Address(value=v), f"[ipv4-addr:value = '{v}']", octi
    if t == "ipv6-addr":
        return stix2.IPv6Address(value=v), f"[ipv6-addr:value = '{v}']", octi
    if t == "domain-name":
        return stix2.DomainName(value=v), f"[domain-name:value = '{v}']", octi
    if t == "url":
        return stix2.URL(value=v), f"[url:value = '{v}']", octi
    if t == "email-addr":
        return stix2.EmailAddress(value=v), f"[email-addr:value = '{v}']", octi
    if t.startswith("file:"):
        algo = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[t.split(":", 1)[1]]
        return (
            stix2.File(hashes={algo: v}),
            f"[file:hashes.'{algo}' = '{v}']",
            octi,
        )
    raise ValueError(f"Unsupported ioc_type: {t}")


def _build_entity(
    entity: Entity, author_id: str, attack_index: AttackIndex | None = None
) -> stix2.base._STIXBase:
    cls = _ENTITY_CLASSES[entity.type]
    kwargs: dict = {"name": entity.name, "created_by_ref": author_id}
    if entity.description:
        kwargs["description"] = entity.description
    if entity.aliases and entity.type in ("threat-actor", "intrusion-set", "malware", "tool", "campaign"):
        kwargs["aliases"] = entity.aliases
    if entity.type == "attack-pattern":
        # Verify the ATT&CK id (and canonicalise the name) so the technique
        # merges cleanly with OpenCTI's ATT&CK dataset. Only a real id is kept.
        canonical_name, verified_id = resolve_technique(
            entity.name, entity.mitre_id, attack_index
        )
        kwargs["name"] = canonical_name
        if verified_id:
            kwargs["external_references"] = [
                stix2.ExternalReference(source_name="mitre-attack", external_id=verified_id)
            ]
    # Type-specific required properties (STIX 2.1).
    if entity.type == "identity":
        # OpenCTI derives entity kind from identity_class. A targeted *sector*
        # uses the STIX "class" value, which OpenCTI ingests as a Sector.
        ic = (entity.identity_class or "organization").lower()
        kwargs["identity_class"] = "class" if ic == "sector" else ic
    elif entity.type == "malware":
        # We extract families, not specific samples, by default.
        kwargs["is_family"] = True
    elif entity.type == "location":
        # Location MUST carry at least one geo property; we only have a name,
        # so mirror it into the open-vocab `region` to produce a valid object.
        kwargs["region"] = entity.name
    return cls(allow_custom=True, **kwargs)


def build_bundle(
    extraction: Extraction,
    author_name: str = "AI STIX Mapper",
    attack_index: AttackIndex | None = None,
) -> stix2.Bundle:
    now = _now()
    author = stix2.Identity(name=author_name, identity_class="organization")

    objects: list = [author]
    ref_to_id: dict[str, str] = {}

    # Entities (SDOs)
    for entity in extraction.entities:
        obj = _build_entity(entity, author.id, attack_index)
        ref_to_id[entity.ref] = obj.id
        objects.append(obj)

    # Indicators + observables + based-on
    for ioc in extraction.indicators:
        sco, pattern, octi_type = _build_observable(ioc)
        indicator = stix2.Indicator(
            name=ioc.name or ioc.value,
            description=ioc.description,
            pattern=pattern,
            pattern_type="stix",
            valid_from=now,
            created_by_ref=author.id,
            allow_custom=True,
            x_opencti_main_observable_type=octi_type,
        )
        ref_to_id[ioc.ref] = indicator.id
        based_on = stix2.Relationship(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=sco.id,
            created_by_ref=author.id,
        )
        objects.extend([indicator, sco, based_on])

    # Relationships (SROs) — skip any that reference unknown refs.
    for rel in extraction.relationships:
        src = ref_to_id.get(rel.source_ref)
        tgt = ref_to_id.get(rel.target_ref)
        if not src or not tgt:
            continue
        objects.append(
            stix2.Relationship(
                relationship_type=rel.relationship_type,
                source_ref=src,
                target_ref=tgt,
                description=rel.description,
                created_by_ref=author.id,
            )
        )

    # Report container referencing everything (except the author identity itself).
    published = _parse_date(extraction.published) or now
    report = stix2.Report(
        name=extraction.report_name,
        description=extraction.report_description,
        published=published,
        report_types=extraction.report_types or ["threat-report"],
        labels=extraction.labels or None,
        object_refs=[o.id for o in objects if o is not author],
        created_by_ref=author.id,
    )
    objects.append(report)

    return stix2.Bundle(objects=objects, allow_custom=True)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
