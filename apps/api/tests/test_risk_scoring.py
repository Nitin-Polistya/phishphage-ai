from app.schemas.analysis import ThreatSignal, ThreatSeverity
from app.services.risk_scoring import calculate_risk_score, classify_risk_score, calculate_confidence


def _mk(code, score, category='x', sev=ThreatSeverity.low):
    return ThreatSignal(code=code, category=category, severity=sev, title=code, description='', score=score)


def test_no_signals_safe():
    score = calculate_risk_score([])
    assert score == 0
    assert classify_risk_score(score) == 'safe'


def test_low_only():
    s = [_mk('a', 10), _mk('b', 10)]
    score = calculate_risk_score(s)
    assert score == 20
    assert classify_risk_score(score) == 'safe'


def test_medium_combined():
    s = [_mk('a', 30), _mk('b', 30)]
    score = calculate_risk_score(s)
    assert score == 60
    assert classify_risk_score(score) == 'suspicious'


def test_high_combined_and_cap():
    s = [_mk('a', 60), _mk('b', 60)]
    score = calculate_risk_score(s)
    assert score == 100
    assert classify_risk_score(score) == 'phishing'


def test_duplicate_signals_not_double_counted():
    s = [_mk('a', 30), _mk('a', 30)]
    score = calculate_risk_score(s)
    assert score == 30


def test_confidence_bounds():
    s = [_mk('a', 60), _mk('b', 30)]
    score = calculate_risk_score(s)
    conf = calculate_confidence(score, s)
    assert 0.0 <= conf <= 1.0
