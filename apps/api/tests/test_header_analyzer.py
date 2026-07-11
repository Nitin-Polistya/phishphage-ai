from app.analyzers.header_analyzer import analyze_headers


def test_valid_headers():
    headers = {'from': 'alice@example.com', 'message-id': '<1@example.com>'}
    signals = analyze_headers(headers, 'alice@example.com', 'Alice', None, '<1@example.com>')
    assert not signals


def test_missing_sender():
    headers = {}
    signals = analyze_headers(headers, None, None, None, None)
    codes = {s.code for s in signals}
    assert 'header_missing_sender' in codes


def test_malformed_sender():
    headers = {}
    signals = analyze_headers(headers, 'alice-at-example', 'Alice', None, None)
    codes = {s.code for s in signals}
    assert 'header_malformed_sender' in codes


def test_replyto_mismatch():
    headers = {'reply-to': 'bob@other.com'}
    signals = analyze_headers(headers, 'alice@example.com', 'Alice', None, None)
    codes = {s.code for s in signals}
    assert 'header_replyto_mismatch' in codes


def test_missing_message_id():
    headers = {}
    signals = analyze_headers(headers, 'a@b.com', 'Alice', None, None)
    codes = {s.code for s in signals}
    assert 'header_missing_message_id' in codes


def test_spf_dkim_dmarc_fail():
    headers = {'authentication-results': 'mx.example.com; spf=fail smtp.mailfrom=bad.com; dkim=fail; dmarc=fail'}
    signals = analyze_headers(headers, 'a@b.com', 'Alice', None, '<1>')
    codes = {s.code for s in signals}
    assert 'header_spf_fail' in codes
    assert 'header_dkim_fail' in codes
    assert 'header_dmarc_fail' in codes
