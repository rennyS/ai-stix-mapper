"""Builder tests — no network / API key required."""

import json

from ai_stix_mapper.builder import build_bundle
from ai_stix_mapper.schema import Entity, Extraction, Indicator, Relationship


def _sample() -> Extraction:
    return Extraction(
        report_name="Test Intrusion",
        report_description="A sample report.",
        published="2026-01-15T00:00:00Z",
        labels=["apt", "test"],
        report_types=["threat-report"],
        entities=[
            Entity(ref="is-1", type="intrusion-set", name="APT-Test", aliases=["TestBear"]),
            Entity(ref="ta-1", type="threat-actor", name="John Persona"),
            Entity(ref="mw-1", type="malware", name="TestRat"),
            Entity(ref="cve-1", type="vulnerability", name="CVE-2026-0001"),
            Entity(ref="id-1", type="identity", name="Financial Services",
                   identity_class="sector"),
        ],
        indicators=[
            Indicator(ref="ioc-1", ioc_type="ipv4-addr", value="203.0.113.5"),
            Indicator(ref="ioc-2", ioc_type="domain-name", value="evil.example.com"),
            Indicator(
                ref="ioc-3",
                ioc_type="file:sha256",
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ],
        relationships=[
            Relationship(source_ref="is-1", target_ref="mw-1", relationship_type="uses"),
            Relationship(source_ref="is-1", target_ref="ta-1", relationship_type="attributed-to"),
            Relationship(source_ref="is-1", target_ref="id-1", relationship_type="targets"),
            Relationship(source_ref="mw-1", target_ref="cve-1", relationship_type="exploits"),
            Relationship(source_ref="ioc-1", target_ref="mw-1", relationship_type="indicates"),
            # dangling ref should be dropped silently
            Relationship(source_ref="ghost", target_ref="mw-1", relationship_type="uses"),
        ],
    )


def _objs(extraction=None):
    return json.loads(build_bundle(extraction or _sample()).serialize())["objects"]


def test_bundle_has_no_observed_data():
    bundle = build_bundle(_sample())
    types = [o["type"] for o in json.loads(bundle.serialize())["objects"]]
    assert "observed-data" not in types


def test_iocs_become_indicator_plus_observable():
    bundle = build_bundle(_sample())
    types = [o["type"] for o in json.loads(bundle.serialize())["objects"]]
    assert types.count("indicator") == 3
    # one SCO per indicator
    for sco in ("ipv4-addr", "domain-name", "file"):
        assert sco in types
    # based-on links indicator -> SCO
    based_on = [
        o for o in json.loads(bundle.serialize())["objects"]
        if o["type"] == "relationship" and o["relationship_type"] == "based-on"
    ]
    assert len(based_on) == 3


def test_report_references_objects_and_dangling_dropped():
    objs = _objs()
    report = next(o for o in objs if o["type"] == "report")
    assert report["object_refs"]
    assert report["report_types"] == ["threat-report"]
    rels = [o for o in objs if o["type"] == "relationship"]
    # 3 based-on + 5 valid SROs; the ghost-ref relationship is dropped
    assert sum(1 for r in rels if r["relationship_type"] != "based-on") == 5


def test_named_group_is_intrusion_set_not_threat_actor():
    objs = _objs()
    intrusion_sets = [o for o in objs if o["type"] == "intrusion-set"]
    assert any(o["name"] == "APT-Test" for o in intrusion_sets)
    # the persona stays a threat-actor and is attributed from the intrusion set
    assert any(o["type"] == "threat-actor" and o["name"] == "John Persona" for o in objs)


def test_sector_identity_uses_class():
    ident = next(o for o in _objs() if o["type"] == "identity" and o["name"] == "Financial Services")
    assert ident["identity_class"] == "class"


def test_indicators_carry_opencti_observable_type():
    indicators = [o for o in _objs() if o["type"] == "indicator"]
    assert indicators
    by_pattern = {o["pattern"]: o.get("x_opencti_main_observable_type") for o in indicators}
    assert "[ipv4-addr:value = '203.0.113.5']" in by_pattern
    assert by_pattern["[ipv4-addr:value = '203.0.113.5']"] == "IPv4-Addr"
    assert all(v for v in by_pattern.values())
