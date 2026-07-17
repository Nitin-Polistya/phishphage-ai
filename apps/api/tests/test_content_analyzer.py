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


def test_capitalization_ignores_urls_domains_acronyms_and_encoded_tokens():
    prose = (
        'Cline AI monthly update is ready for the community. '
        'Read https://CLINE.BOT/ACCOUNT/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '
        'and reference MIME DKIM SPF HTML QP =3DTRACKINGTOKEN.'
    )
    codes = {signal.code for signal in analyze_content('CLINE AI UPDATE', prose, '', None)}
    assert 'content_excessive_caps' not in codes


def test_multiple_meaningful_all_caps_words_remain_detectable():
    prose = (
        'URGENTLY VERIFY ACCOUNT ACCESS IMMEDIATELY BEFORE SERVICES TERMINATE '
        'because this security notice requires your attention today.'
    )
    codes = {signal.code for signal in analyze_content(None, prose, '', None)}
    assert 'content_excessive_caps' in codes
