# AI STIX Mapper

Turn a threat report — a **PDF** or a **web page** — into a [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) bundle ready to import into [OpenCTI](https://www.opencti.io/).

An OpenAI model reads the report, extracts entities and IOCs, and infers the STIX 2.1 relationships between them. The result is packaged as a STIX **Report** container plus all referenced objects in a single bundle.

## Design rules

- **No `observed-data`.** IOCs are modelled the OpenCTI-friendly way: an **`indicator`** (with a STIX pattern) plus the matching **cyber-observable (SCO)**, linked by a `based-on` relationship.
- **One bundle, one Report.** Everything the model finds is referenced by a STIX `Report` so OpenCTI ingests it as a single container.
- **OpenCTI import is draft-only.** Direct import (optional) always lands in a **draft workspace** so a human validates it before it touches the live knowledge base.
- **OpenAI endpoint.** Uses the OpenAI API; set `OPENAI_BASE_URL` to point at any OpenAI-compatible endpoint.

## Install

```bash
pip install -e .
# optional, for direct OpenCTI draft import:
pip install -e ".[opencti]"
```

## Configure

```bash
cp .env.example .env
# then edit .env
```

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | required |
| `OPENAI_MODEL` | defaults to `gpt-4o` |
| `OPENAI_BASE_URL` | optional, for OpenAI-compatible endpoints |
| `OPENCTI_URL` / `OPENCTI_TOKEN` | only needed for `--push-opencti` |

## Use

```bash
# Local PDF -> bundle file
stix-mapper report.pdf

# Web page -> bundle file at a chosen path
stix-mapper https://example.com/threat-report -o intel.stix.json

# Also import into OpenCTI as a draft for review
stix-mapper report.pdf --push-opencti
```

The bundle is written as JSON. Import it manually via **Data → Import** in OpenCTI, or use `--push-opencti` to drop it straight into a draft workspace.

## What gets produced

| STIX object | From |
| --- | --- |
| `report` | the document itself (container) |
| `indicator` + SCO (`ipv4-addr`, `domain-name`, `url`, `file`, `email-addr`, …) | IOCs, joined by `based-on` |
| `threat-actor`, `intrusion-set`, `malware`, `tool`, `attack-pattern`, `campaign`, `vulnerability`, `identity`, `infrastructure`, `location`, `course-of-action` | named entities |
| `relationship` | inferred SROs (`uses`, `targets`, `indicates`, `attributed-to`, `mitigates`, `exploits`, …) |

> Direct draft import requires OpenCTI 6.2+ (draft workspaces) and a `pycti` release that supports them.

## Layout

```
ai_stix_mapper/
  cli.py            # stix-mapper command
  config.py         # env / .env settings
  extractors.py     # PDF + web page -> text
  llm.py            # OpenAI structured extraction
  schema.py         # pydantic extraction model (no observed-data)
  prompts.py        # analyst system prompt
  builder.py        # Extraction -> stix2 Bundle
  opencti_client.py # optional draft-only import
```
