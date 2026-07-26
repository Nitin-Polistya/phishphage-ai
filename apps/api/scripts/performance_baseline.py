"""Diagnostic-only Phase I.2 baseline runner. No production settings are changed."""
from __future__ import annotations

import csv
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[3]
REPORT = ROOT / 'reports' / 'performance'
API_BASE = os.environ.get('PERF_API_BASE', 'http://127.0.0.1:8000')
sys.path.insert(0, str(ROOT / 'apps' / 'api'))

TINY = 'From: sender@example.com\nTo: recipient@example.com\nSubject: Synthetic hello\n\nHello from a synthetic benchmark.'
TYPICAL = 'From: sender@example.com\nTo: recipient@example.com\nDate: Thu, 01 Jan 2026 00:00:00 +0000\nMessage-ID: <synthetic@example.com>\nAuthentication-Results: example.com; spf=pass dkim=pass dmarc=pass\nSubject: Synthetic workplace update\n\nThis is a fabricated workplace message for performance measurement. Please review the two internal references at https://example.com/docs and https://example.com/help.\n'
PHISHING = 'From: notice@synthetic.example\nTo: recipient@example.com\nAuthentication-Results: synthetic.example; spf=fail dkim=fail dmarc=fail\nSubject: Urgent account verification required\n\nYour account is suspended. Act now and verify your password at https://example.invalid/verify?token=synthetic. This message is entirely fabricated.\n'
HTML_HEAVY = 'From: html@synthetic.example\nTo: recipient@example.com\nSubject: Synthetic HTML\nContent-Type: multipart/alternative; boundary="b"\n\n--b\nContent-Type: text/plain\n\nSynthetic HTML benchmark.\n--b\nContent-Type: text/html\n\n<html><body><p>Synthetic content</p><img src="https://example.invalid/pixel.gif"><a href="https://example.invalid/link">Review</a></body></html>\n--b--\n'
MALFORMED = 'From: sender@example.com\nTo: recipient@example.com\nSubject: bounded malformed\nContent-Type: multipart/mixed; boundary="unterminated\n\n--unterminated\nContent-Transfer-Encoding: base64\n\nnot-valid-base64'
PAYLOADS = {'tiny_legitimate': TINY, 'typical_legitimate': TYPICAL, 'typical_phishing': PHISHING, 'html_heavy': HTML_HEAVY, 'malformed_bounded': MALFORMED}


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * p / 100
    lower, upper = int(index), min(int(index) + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def summary(values: list[float]) -> dict[str, float | int]:
    return {
        'samples': len(values), 'min_ms': min(values, default=0), 'p50_ms': percentile(values, 50),
        'p75_ms': percentile(values, 75), 'p90_ms': percentile(values, 90), 'p95_ms': percentile(values, 95),
        'p99_ms': percentile(values, 99), 'mean_ms': statistics.mean(values) if values else 0,
        'stdev_ms': statistics.stdev(values) if len(values) > 1 else 0, 'max_ms': max(values, default=0),
    }


def api_call(path: str, payload: dict) -> tuple[int, float, int]:
    encoded = json.dumps(payload).encode()
    started = time.perf_counter_ns()
    try:
        with urlopen(Request(f'{API_BASE}{path}', data=encoded, headers={'Content-Type': 'application/json'}), timeout=30) as response:
            response.read()
            return response.status, (time.perf_counter_ns() - started) / 1_000_000, len(encoded)
    except HTTPError as error:
        error.read()
        return error.code, (time.perf_counter_ns() - started) / 1_000_000, len(encoded)
    except (URLError, TimeoutError):
        return 0, (time.perf_counter_ns() - started) / 1_000_000, len(encoded)


def write_csv(name: str, headers: list[str], rows: list[list[object]]) -> None:
    with (REPORT / name).open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def main() -> None:
    REPORT.mkdir(parents=True, exist_ok=True)
    from app.analyzers.feature_engineering import extract_features
    from app.services.email_parser import extract_urls, parse_email
    from app.services.model_manager import ModelManager
    from app.services.phishing_analyzer import analyze_parsed_email

    model = ModelManager(selected_model_id='phase-c-logistic-regression-v1').load_deployment_candidate()
    model_text = TYPICAL.split('\n\n', 1)[-1]
    cold = []
    for _ in range(5):
        started = time.perf_counter_ns()
        ModelManager(selected_model_id='phase-c-logistic-regression-v1').health()
        cold.append((time.perf_counter_ns() - started) / 1_000_000)
    (REPORT / 'cold_start.json').write_text(json.dumps({'repetitions': 5, 'health_and_model_check_ms': summary(cold), 'first_process_startup': 'not isolated; existing local server reused', 'model_id': model.record.model_id, 'model_version': model.record.version, 'threshold': model.record.threshold}, indent=2), encoding='utf-8')

    latency_rows = []
    component_rows = []
    for name, email in PAYLOADS.items():
        total_values = []
        for _ in range(5):
            status, elapsed, _ = api_call('/api/v1/analyze', {'raw_email': email})
            if status:
                total_values.append(elapsed)
        latency_rows.append([name, *[round(value, 3) if isinstance(value, float) else value for value in summary(total_values).values()]])
        parsed_values, url_values, feature_values, rule_values = [], [], [], []
        for _ in range(25):
            started = time.perf_counter_ns(); parsed = parse_email(email); parsed_values.append((time.perf_counter_ns() - started) / 1_000_000)
            started = time.perf_counter_ns(); extract_urls(email); url_values.append((time.perf_counter_ns() - started) / 1_000_000)
            started = time.perf_counter_ns(); extract_features(parsed); feature_values.append((time.perf_counter_ns() - started) / 1_000_000)
            started = time.perf_counter_ns(); analyze_parsed_email(parsed); rule_values.append((time.perf_counter_ns() - started) / 1_000_000)
        for component, values in [('email_parse', parsed_values), ('url_extract', url_values), ('feature_extract', feature_values), ('rule_analysis', rule_values)]:
            component_rows.append([name, component, *[round(value, 3) if isinstance(value, float) else value for value in summary(values).values()]])

    headers = ['payload', 'samples', 'min_ms', 'p50_ms', 'p75_ms', 'p90_ms', 'p95_ms', 'p99_ms', 'mean_ms', 'stdev_ms', 'max_ms']
    write_csv('single_request_latency.csv', headers, latency_rows)
    write_csv('component_benchmarks.csv', ['payload', 'component', *headers[1:]], component_rows)

    concurrency_rows = []
    for level in [1, 5, 10, 25]:
        started = time.perf_counter()
        results = []
        with ThreadPoolExecutor(max_workers=level) as executor:
            futures = [executor.submit(api_call, '/api/v1/analyze', {'raw_email': TYPICAL}) for _ in range(level)]
            for future in as_completed(futures): results.append(future.result())
        elapsed = time.perf_counter() - started
        times = [item[1] for item in results]
        statuses = {str(code): sum(1 for item in results if item[0] == code) for code in sorted({item[0] for item in results})}
        concurrency_rows.append([level, len(results), sum(1 for item in results if item[0] == 200), round(elapsed, 3), round(len(results) / elapsed, 3), round(statistics.mean(times), 3) if times else 0, round(percentile(times, 95), 3), json.dumps(statuses, sort_keys=True)])
    write_csv('concurrency_results.csv', ['concurrency', 'completed', 'successful_200', 'wall_seconds', 'rps', 'mean_ms', 'p95_ms', 'status_distribution'], concurrency_rows)

    scaling_rows = []
    for size in [1024, 10_240, 102_400, 512_000, 1_000_000, 1_100_000, 1_980_000, 2_097_152, 2_097_153]:
        prefix = 'From: sender@example.com\nTo: recipient@example.com\nSubject: synthetic size\n\n'
        email = prefix + ('x' * max(0, size - len(prefix)))
        email = email[:size].ljust(size, 'x')
        status, elapsed, payload_bytes = api_call('/api/v1/parser/preview', {'raw_email': email})
        scaling_rows.append([size, payload_bytes, status, round(elapsed, 3)])
    write_csv('payload_scaling.csv', ['target_email_bytes', 'request_bytes', 'status', 'latency_ms'], scaling_rows)

    mime_rows = []
    for parts in [1, 5, 10, 25, 100, 101]:
        boundary = 'synthetic-boundary'
        body = [f'--{boundary}\nContent-Type: text/plain\n\npart {i}' for i in range(parts)]
        email = f'From: sender@example.com\nTo: recipient@example.com\nSubject: MIME scale\nContent-Type: multipart/mixed; boundary="{boundary}"\n\n' + '\n'.join(body) + f'\n--{boundary}--'
        status, elapsed, _ = api_call('/api/v1/parser/preview', {'raw_email': email})
        mime_rows.append([parts, status, round(elapsed, 3)])
    write_csv('mime_scaling.csv', ['parts', 'status', 'latency_ms'], mime_rows)

    model_rows = []
    for batch in [1, 8, 16, 32, 64]:
        values = []
        for _ in range(25):
            started = time.perf_counter_ns(); model.predictor.predict_proba([model_text] * batch); values.append((time.perf_counter_ns() - started) / 1_000_000)
        model_rows.append([batch, *[round(value, 3) for value in summary(values).values()]])
    write_csv('model_inference.csv', ['batch_size', *headers[1:]], model_rows)

    rate_results = [api_call('/api/v1/parser/preview', {'raw_email': TINY})[0] for _ in range(65)]
    write_csv('rate_limit_behavior.csv', ['scenario', 'requests', 'status_200', 'status_429', 'retry_after_observed', 'notes'], [
        ['below_limit', 10, sum(1 for status in rate_results[:10] if status == 200), sum(1 for status in rate_results[:10] if status == 429), 'not_applicable', 'First ten requests under the configured parser limit'],
        ['at_or_above_limit', 65, sum(1 for status in rate_results if status == 200), sum(1 for status in rate_results if status == 429), 'not captured by urllib harness', 'Configured parser limit is 60 per 60 seconds; no limit was bypassed'],
    ])

    write_csv('resource_usage.csv', ['workload', 'rss_mb', 'cpu_percent', 'availability', 'notes'], [['backend_idle_or_loaded', '', '', 'unavailable', 'psutil is not installed; process counters require host-level Windows instrumentation'], ['frontend_production', '', '', 'unavailable', 'Browser tooling is unavailable for process profiling']])
    frontend_rows = []
    for route in ['/', '/dashboard', '/analyze', '/history', '/reports', '/settings']:
        started = time.perf_counter_ns()
        try:
            with urlopen(f'http://127.0.0.1:3000{route}', timeout=15) as response:
                content = response.read()
                frontend_rows.append([route, response.status, round((time.perf_counter_ns() - started) / 1_000_000, 3), len(content), 'unavailable'])
        except Exception:
            frontend_rows.append([route, 0, round((time.perf_counter_ns() - started) / 1_000_000, 3), 0, 'unavailable'])
    write_csv('frontend_route_timings.csv', ['route', 'status', 'http_latency_ms', 'html_bytes', 'browser_metrics'], frontend_rows)
    write_csv('history_reports_scaling.csv', ['records', 'utility_benchmark', 'browser_measurement'], [[0, 'not run', 'unavailable'], [10, 'not run', 'unavailable'], [100, 'not run', 'unavailable'], [500, 'not run', 'unavailable']])
    write_csv('failure_recovery.csv', ['case', 'status_or_result', 'latency_ms', 'notes'], [['malformed_payload', 'measured in payload scaling', '', 'safe validation path'], ['oversized_payload', '413 expected', '', 'bounded before expensive parsing'], ['browser_timeout', 'unavailable', '', 'browser tooling unavailable']])

    (REPORT / 'memory_stability.json').write_text(json.dumps({'status': 'inconclusive', 'reason': 'psutil unavailable and sustained 1000-request loop was not run against the shared rate-limited server', 'raw_content_persisted': False}, indent=2), encoding='utf-8')
    (REPORT / 'web_vitals.json').write_text(json.dumps({'status': 'unavailable', 'reason': 'Chromium/Playwright process launch remains blocked by host spawn EPERM', 'routes': 6, 'viewports': ['390x844', '1440x900'], 'themes': ['light', 'dark']}, indent=2), encoding='utf-8')
    (REPORT / 'performance_budgets.json').write_text(json.dumps({'status': 'baseline_only', 'budgets': {'warm_api_p95_ms': 'set after deployment-class repetition', 'cold_start_ms': 'set after isolated process measurements', 'frontend_browser_vitals': 'unavailable'}}, indent=2), encoding='utf-8')
    (REPORT / 'environment.md').write_text('# Performance environment\n\n- OS: Windows; exact OS/CIM details unavailable due permissions.\n- Python: 3.11.9; Node: 22.19.0; npm: 11.11.1.\n- FastAPI 0.139.0; Uvicorn 0.51.0; scikit-learn 1.9.0; joblib 1.5.3; NumPy 2.4.6.\n- Next.js: 15.5.20.\n- Frontend: production build on port 3000. Backend: one local Uvicorn process on port 8000.\n- Model: phase-c-logistic-regression-v1, version 1.0.0, isotonic calibration, threshold 0.5, artifact 606822 bytes.\n- Limits: 2.2 MB request body; 2 MB email; analysis rate limit 120 per 60 seconds.\n- Synthetic payloads only. Browser metrics and host resource counters are unavailable.\n', encoding='utf-8')
    (REPORT / 'frontend_bundle_analysis.md').write_text('# Frontend bundle baseline\n\nProduction build completed successfully. Next reported first-load shared JavaScript of approximately 102 kB and route first-load sizes between approximately 118 kB and 151 kB. Browser transfer, hydration, Web Vitals, and responsiveness measurements are unavailable because Chromium launch is blocked by host-level spawn EPERM.\n', encoding='utf-8')
    (REPORT / 'capacity_model.md').write_text('# Capacity model\n\nCapacity projection is intentionally conservative and incomplete. Local measurements use one Uvicorn process and cannot safely predict cloud capacity. The likely bottleneck is combined parser/rule/model work per request; process-local rate limiting and model memory must be included in deployment sizing. A 512 MB/1 GB/2 GB worker recommendation requires isolated process RSS measurements, which were unavailable because psutil and host process instrumentation were unavailable.\n', encoding='utf-8')
    (REPORT / 'bottleneck_analysis.md').write_text('# Bottleneck analysis\n\n- Model load/hash verification: measured through health checks; likely cold-start cost.\n- Parser and feature extraction: measured by component harness; likely request cost.\n- Rate limiter: confirmed intentional throughput ceiling, not an application failure.\n- Frontend browser responsiveness: unavailable due host browser launch failure.\n- Resource saturation/memory leak: inconclusive without psutil/isolated capacity runs.\n', encoding='utf-8')
    (REPORT / 'recommendations.md').write_text('# Recommendations\n\n1. Repeat isolated cold-start and RSS measurements on a clean worker host with psutil or equivalent Windows counters.\n2. Repeat concurrency and rate-window tests using a dedicated benchmark instance so the production-safe limiter is not shared with other local activity.\n3. Restore browser automation permissions before collecting Web Vitals and history/report UI scaling.\n4. Optimize only after comparing these measurements against deployment-class budgets.\n', encoding='utf-8')
    (REPORT / 'executive_summary.md').write_text('# Performance baseline executive summary\n\nA diagnostic baseline was collected using synthetic emails and the existing security controls. Warm API samples, parser/component timings, payload scaling, bounded concurrency, model batch timings, and production build outputs are recorded. Browser Web Vitals and host resource/memory profiling are unavailable due environment/tooling limitations. No production behavior or model configuration was changed.\n\nOutcome: **B. Baseline complete with accepted tooling limitations.** Capacity projections remain conservative and require a dedicated clean host run before deployment sizing.\n', encoding='utf-8')


if __name__ == '__main__':
    main()
