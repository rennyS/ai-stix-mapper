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
        entities=[
            Entity(ref="ta-1", type="threat-actor", name="APT-Test", aliases=["TestBear"]),
            Entity(ref="mw-1", type="malware", name="TestRat"),
            Entity(ref="cve-1", type="vulnerability", name="CVE-2026-0001"),
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
            Relationship(source_ref="ta-1", target_ref="mw-1", relationship_type="uses"),
            Relationship(source_ref="mw-1", target_ref="cve-1", relationship_type="exploits"),
            Relationship(source_ref="ioc-1", target_ref="mw-1", relationship_type="indicates"),
            # dangling ref should be dropped silently
            Relationship(source_ref="ghost", target_ref="mw-1", relationship_type="uses"),
        ],
    )


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
    objs = json.loads(build_bundle(_sample()).serialize())["objects"]
    report = next(o for o in objs if o["type"] == "report")
    assert report["object_refs"]
    rels = [o for o in objs if o["type"] == "relationship"]
    # 3 based-on + 3 valid SROs; the ghost ref relationship is dropped
    assert sum(1 for r in rels if r["relationship_type"] != "based-on") == 3
