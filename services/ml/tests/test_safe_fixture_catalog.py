from collections import Counter

from fixtures.safe_email_cases import ALL_CASES, RAW_CASES


def test_fixture_catalog_has_required_scenario_counts():
    counts = Counter(case['category'] for case in ALL_CASES)
    assert counts['phishing'] >= 15
    assert counts['legitimate'] >= 15
    assert counts['hard_negative'] >= 10
    assert counts['disagreement'] >= 5
    assert counts['incomplete'] >= 5


def test_raw_fixtures_are_safe_and_include_facebook_regression():
    assert all('From:' in case['raw_email'] and 'Subject:' in case['raw_email'] for case in RAW_CASES)
    assert all('.example.' in case['raw_email'] or '@example.' in case['raw_email'] for case in RAW_CASES)
    assert any(case['scenario'] == 'facebook_impersonation' for case in RAW_CASES)
