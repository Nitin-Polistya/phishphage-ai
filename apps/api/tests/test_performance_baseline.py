from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.performance_baseline import PAYLOADS, percentile, summary


def test_synthetic_payload_catalog_is_privacy_safe():
    assert set(PAYLOADS) == {'tiny_legitimate', 'typical_legitimate', 'typical_phishing', 'html_heavy', 'malformed_bounded'}
    assert all('synthetic' in value.casefold() or 'example.com' in value for value in PAYLOADS.values())
    assert not any('@gmail.com' in value or '@outlook.com' in value for value in PAYLOADS.values())


def test_percentiles_and_empty_summary_are_deterministic():
    values = [1.0, 2.0, 3.0, 4.0]
    assert percentile(values, 50) == 2.5
    assert percentile([], 95) == 0.0
    result = summary(values)
    assert result['samples'] == 4
    assert result['p95_ms'] >= result['p50_ms']


def test_generated_report_schema_is_machine_readable():
    report_dir = Path(__file__).resolve().parents[3] / 'reports' / 'performance'
    expected = ['cold_start.json', 'single_request_latency.csv', 'component_benchmarks.csv', 'concurrency_results.csv']
    for name in expected:
        path = report_dir / name
        assert path.exists()
        if path.suffix == '.json':
            json.loads(path.read_text(encoding='utf-8'))
        else:
            with path.open(newline='', encoding='utf-8') as handle:
                rows = list(csv.reader(handle))
            assert len(rows) > 1
            assert all(len(row) == len(rows[0]) for row in rows)
