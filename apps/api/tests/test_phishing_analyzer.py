from app.services.phishing_analyzer import analyze_parsed_email
from app.services.email_parser import parse_email


def test_analyze_legitimate_email():
    raw = 'From: alice@example.com\nSubject: Hello\n\nThis is fine.'
    parsed = parse_email(raw)
    res = analyze_parsed_email(parsed)
    assert res.classification.value == 'safe' or res.risk_score < 30


def test_analyze_phishing_combined():
    raw = 'From: attacker@bad.com\nSubject: URGENT: Verify your password\n\nClick here: http://bit.ly/evil\n'
    parsed = parse_email(raw)
    res = analyze_parsed_email(parsed)
    assert res.risk_score >= 30
    assert any('credential' in s.code or 'url_shortener' in s.code for s in res.signals)
