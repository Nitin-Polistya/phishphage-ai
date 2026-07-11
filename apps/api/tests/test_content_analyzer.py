from app.analyzers.content_analyzer import analyze_content


def test_legitimate_content():
    signals = analyze_content('Hello', 'This is a normal message', None, 'Alice')
    assert not signals


def test_urgency_language():
    signals = analyze_content('Urgent: action required', 'Please act now', None, None)
    codes = {s.code for s in signals}
    assert 'content_urgency' in codes


def test_credential_request():
    signals = analyze_content('Verify your password', 'Please verify your password', None, None)
    codes = {s.code for s in signals}
    assert 'content_credential_request' in codes


def test_excessive_caps_and_punct():
    subj = 'THIS IS URGENT!!!'
    signals = analyze_content(subj, None, None, None)
    codes = {s.code for s in signals}
    assert 'content_excessive_caps' in codes or 'content_excessive_punct' in codes
