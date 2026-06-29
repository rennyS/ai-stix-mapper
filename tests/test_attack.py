"""ATT&CK id verification — uses an in-memory index, no network."""

import json

from ai_stix_mapper.attack import AttackIndex, normalize_id, resolve_technique
from ai_stix_mapper.builder import build_bundle
from ai_stix_mapper.schema import Entity, Extraction


def _index() -> AttackIndex:
    return AttackIndex({"T1566": "Phishing", "T1566.001": "Spearphishing Attachment"})


def test_normalize_id():
    assert normalize_id("t1566") == "T1566"
    assert normalize_id(" T1566.001 ") == "T1566.001"
    assert normalize_id("T156") is None
    assert normalize_id("not-an-id") is None
    assert normalize_id(None) is None


def test_resolve_keeps_real_id_and_canonicalises_name():
    name, tid = resolve_technique("phishing", "t1566", _index())
    assert tid == "T1566"
    assert name == "Phishing"  # normalised to canonical spelling


def test_resolve_recovers_id_from_name_when_id_wrong():
    # T9999 is well-formed but not real -> recover from the name instead.
    name, tid = resolve_technique("Spearphishing Attachment", "T9999", _index())
    assert tid == "T1566.001"


def test_resolve_drops_unverifiable_id_with_catalog():
    name, tid = resolve_technique("Totally Made Up", "T9999", _index())
    assert tid is None


def test_resolve_without_catalog_keeps_only_wellformed():
    assert resolve_technique("x", "T1566", None) == ("x", "T1566")
    assert resolve_technique("x", "T999", None) == ("x", None)


def test_builder_drops_bogus_attack_id_without_catalog():
    extraction = Extraction(
        report_name="r",
        report_description="d",
        entities=[Entity(ref="ap-1", type="attack-pattern", name="Phishing", mitre_id="garbage")],
    )
    objs = json.loads(build_bundle(extraction).serialize())["objects"]
    ap = next(o for o in objs if o["type"] == "attack-pattern")
    assert "external_references" not in ap


def test_builder_verifies_attack_id_with_catalog():
    extraction = Extraction(
        report_name="r",
        report_description="d",
        entities=[Entity(ref="ap-1", type="attack-pattern", name="phishing", mitre_id="t1566")],
    )
    objs = json.loads(build_bundle(extraction, attack_index=_index()).serialize())["objects"]
    ap = next(o for o in objs if o["type"] == "attack-pattern")
    assert ap["name"] == "Phishing"
    ext = ap["external_references"][0]
    assert ext["source_name"] == "mitre-attack"
    assert ext["external_id"] == "T1566"
