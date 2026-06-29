"""PDF extraction tests, including password-protected PDFs."""

import fitz  # PyMuPDF
import pytest

from ai_stix_mapper.extractors import PdfPasswordError, extract_text


def _make_encrypted_pdf(path, text: str, user_pw: str) -> None:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    doc.save(
        str(path),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw=user_pw,
        user_pw=user_pw,
    )
    doc.close()


def test_encrypted_pdf_requires_password(tmp_path):
    pdf = tmp_path / "secret.pdf"
    _make_encrypted_pdf(pdf, "TOP SECRET INTEL", "hunter2")

    with pytest.raises(PdfPasswordError):
        extract_text(str(pdf))


def test_encrypted_pdf_wrong_password(tmp_path):
    pdf = tmp_path / "secret.pdf"
    _make_encrypted_pdf(pdf, "TOP SECRET INTEL", "hunter2")

    with pytest.raises(PdfPasswordError):
        extract_text(str(pdf), password="wrong")


def test_encrypted_pdf_correct_password(tmp_path):
    pdf = tmp_path / "secret.pdf"
    _make_encrypted_pdf(pdf, "TOP SECRET INTEL", "hunter2")

    text, label = extract_text(str(pdf), password="hunter2")
    assert "TOP SECRET INTEL" in text
    assert label == str(pdf)
