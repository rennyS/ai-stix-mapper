"""Runtime configuration loaded from environment / .env."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(slots=True)
class Settings:
    openai_api_key: str
    openai_model: str
    openai_base_url: str | None
    opencti_url: str | None
    opencti_token: str | None

    @classmethod
    def load(cls) -> "Settings":
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Copy .env.example to .env and fill it in."
            )
        return cls(
            openai_api_key=key,
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
            opencti_url=os.getenv("OPENCTI_URL") or None,
            opencti_token=os.getenv("OPENCTI_TOKEN") or None,
        )
