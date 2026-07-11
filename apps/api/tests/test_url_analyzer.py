from app.analyzers.url_analyzer import analyze_urls


def test_https_ok():
    signals = analyze_urls(['https://example.com'], sender_domain='example.com')
    assert not signals


def test_http_flagged():
    signals = analyze_urls(['http://example.com'], sender_domain='example.com')
    codes = {s.code for s in signals}
    assert 'url_insecure_scheme' in codes


def test_shortener():
    signals = analyze_urls(['https://bit.ly/abcdef'], sender_domain='legit.com')
    codes = {s.code for s in signals}
    assert 'url_shortener' in codes


def test_ip_host():
    signals = analyze_urls(['http://192.168.0.1/login'], sender_domain='example.com')
    codes = {s.code for s in signals}
    assert 'url_ip_host' in codes


def test_punycode():
    signals = analyze_urls(['http://xn--e1awd7f.com'], sender_domain='example.com')
    codes = {s.code for s in signals}
    assert 'url_punycode' in codes


def test_excessive_subdomains():
    url = 'https://a.b.c.d.e.example.com'
    signals = analyze_urls([url], sender_domain='example.com')
    codes = {s.code for s in signals}
    assert 'url_excessive_subdomains' in codes


def test_long_url_and_keyword_and_userinfo():
    long = 'https://example.com/' + ('a' * 250) + '?action=verify'
    signals = analyze_urls([long, 'http://user:pass@example.com/path'], sender_domain='example.com')
    codes = {s.code for s in signals}
    assert 'url_long' in codes
    assert 'url_suspicious_keyword' in codes
    assert 'url_userinfo' in codes
