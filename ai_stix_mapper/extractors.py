"""Source extraction: turn a PDF or web page into plain text."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import httpx


def _looks_like_url(source: str) -> bool:
    parsed = urlparse(source)
    return parsed.scheme in ("http", "https")


def extract_text(source: str) -> tuple[str, str]:
    """Return (text, source_label) for a local PDF path or a URL.

    Local .pdf files are parsed with PyMuPDF; URLs are fetched and, if HTML,
    stripped to readable text. A URL pointing at a PDF is downloaded and parsed.
    """
    if _looks_like_url(source):
        return _extract_url(source)
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"No such file: {source}")
    if path.suffix.lower() == ".pdf":
        return _extract_pdf_bytes(path.read_bytes()), str(path)
    # Fall back to treating it as a text file.
    return path.read_text(encoding="utf-8", errors="replace"), str(path)


def _extract_pdf_bytes(data: bytes) -> str:
    import fitz  # PyMuPDF

    with fitz.open(stream=data, filetype="pdf") as doc:
        return "\n".join(page.get_text() for page in doc)


def _extract_url(url: str) -> tuple[str, str]:
    headers = {"User-Agent": "ai-stix-mapper/0.1 (+https://github.com/)"}
    with httpx.Client(follow_redirects=True, timeout=30.0, headers=headers) as client:
        resp = client.get(url)
        resp.raise_for_status()
        content_type = resp.headers.get("content-type", "")
        if "application/pdf" in content_type or url.lower().endswith(".pdf"):
            return _extract_pdf_bytes(resp.content), url
        return _html_to_text(resp.text), url


def _html_to_text(html: str) -> str:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()
    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)
