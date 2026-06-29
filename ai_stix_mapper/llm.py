"""OpenAI-backed extraction of STIX structure from report text."""

from __future__ import annotations

from openai import OpenAI

from .config import Settings
from .prompts import SYSTEM_PROMPT
from .schema import Extraction

# Rough character budget so we stay well within context limits. Long reports
# are truncated; chunking/merging is left as a future enhancement.
MAX_CHARS = 120_000


def extract_stix(text: str, settings: Settings) -> Extraction:
    client = OpenAI(api_key=settings.openai_api_key, base_url=settings.openai_base_url)

    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS]

    completion = client.beta.chat.completions.parse(
        model=settings.openai_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Report text:\n\n{text}"},
        ],
        response_format=Extraction,
        temperature=0.1,
    )
    parsed = completion.choices[0].message.parsed
    if parsed is None:
        raise RuntimeError("Model returned no parsable structured output.")
    return parsed
