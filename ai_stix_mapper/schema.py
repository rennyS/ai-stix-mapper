"""Pydantic models describing the structured extraction the LLM must return.

These are deliberately decoupled from the stix2 object model: the LLM works
with simple local refs (e.g. "entity-1") and the mapper resolves those into
real STIX ids when it builds the bundle.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

# STIX 2.1 SDO types the model is allowed to emit.
# observed-data is intentionally excluded — IOCs are modelled as
# indicator + observable (SCO) instead.
ENTITY_TYPES = (
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "threat-actor",
    "tool",
    "vulnerability",
)

EntityType = Literal[
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "threat-actor",
    "tool",
    "vulnerability",
]

IocType = Literal[
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "file:md5",
    "file:sha1",
    "file:sha256",
    "email-addr",
]


class Entity(BaseModel):
    ref: str = Field(description="Local reference id, e.g. 'entity-1'. Unique within the result.")
    type: EntityType
    name: str
    description: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)
    # attack-pattern only
    mitre_id: Optional[str] = Field(default=None, description="e.g. T1566 for ATT&CK techniques")


class Indicator(BaseModel):
    ref: str = Field(description="Local reference id, e.g. 'ioc-1'. Unique within the result.")
    ioc_type: IocType
    value: str = Field(description="The raw IOC value, e.g. '1.2.3.4' or 'evil.example.com'")
    name: Optional[str] = None
    description: Optional[str] = None


class Relationship(BaseModel):
    source_ref: str = Field(description="Local ref of the source entity/indicator")
    target_ref: str = Field(description="Local ref of the target entity/indicator")
    relationship_type: str = Field(
        description="STIX 2.1 relationship type, e.g. 'uses', 'targets', 'indicates', "
        "'attributed-to', 'mitigates', 'exploits'"
    )
    description: Optional[str] = None


class Extraction(BaseModel):
    report_name: str
    report_description: str = Field(description="An executive summary of the report")
    published: Optional[str] = Field(
        default=None, description="ISO 8601 publish date if stated in the source, else null"
    )
    labels: list[str] = Field(default_factory=list, description="Tags / labels for the report")
    entities: list[Entity] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
