import pytest

from phishshield_ml.preprocessing import combine_email_fields, normalize_email_text, validate_training_text


def test_unicode_normalization():
    assert normalize_email_text("e\u0301") == "é"


def test_whitespace_normalization():
    assert normalize_email_text("a\n\n b\t c") == "a b c"


def test_preserves_urls_and_keywords():
    text = normalize_email_text("Urgent verify https://example.com/login user@example.com")
    assert "https://example.com/login" in text
    lowered = text.lower()
    assert "urgent" in lowered
    assert "verify" in lowered


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        validate_training_text("   ")


def test_combine_email_fields():
    assert combine_email_fields("Subject", "Body") == "Subject Body"
