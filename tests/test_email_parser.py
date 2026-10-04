from pathlib import Path

import pytest

from src.services.email_parser import EmailParseError, parse_uploaded_email


BASE = Path(__file__).resolve().parent.parent


def test_blocks_unsupported_extension():
    with pytest.raises(EmailParseError):
        parse_uploaded_email("blocked.exe", b"safe test content")


def test_parses_phishing_eml_safely():
    path = BASE / "data" / "samples" / "phishing_sample.eml"
    parsed = parse_uploaded_email(path.name, path.read_bytes())
    assert "Verify your account" in parsed["subject"]
    assert parsed["sender"]
    assert parsed["urls"]
