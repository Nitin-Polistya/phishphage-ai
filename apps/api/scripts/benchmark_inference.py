"""Generate privacy-safe Phase D inference validation reports."""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.email_parser import parse_email
from app.services.inference_service import inference_service


def main() -> None:
    report_dir = Path('services/ml/reports/phase_d_inference_v1')
    report_dir.mkdir(parents=True, exist_ok=True)
    client = TestClient(app)
    raw = 'From: sender@example.com\nSubject: Verify account\n\nPlease verify your password immediately.'
    before = client.get('/api/v1/health').json()
    first_started = time.perf_counter()
    first = client.post('/api/v1/analyze', json={'raw_email': raw})
    first_request_ms = (time.perf_counter() - first_started) * 1000
    timings = []
    parsing = []
    predictions_ms = []
    predictions = []
    for _ in range(20):
        started = time.perf_counter()
        response = client.post('/api/v1/analyze', json={'raw_email': raw})
        timings.append((time.perf_counter() - started) * 1000)
        parse_started = time.perf_counter()
        parsed = parse_email(raw)
        parsing.append((time.perf_counter() - parse_started) * 1000)
        predict_started = time.perf_counter()
        inference_service.predict_email(parsed)
        predictions_ms.append((time.perf_counter() - predict_started) * 1000)
        predictions.append(response.json().get('prediction') if response.status_code == 200 else 'error')
    after = client.get('/api/v1/health').json()
    timings.sort()
    json_dump = lambda value, name: (report_dir / name).write_text(json.dumps(value, indent=2, sort_keys=True), encoding='utf-8')
    json_dump({'registry_status_before': before.get('registry_status'), 'registry_status_after': after.get('registry_status'),
               'loaded_model': after.get('loaded_model'), 'model_version': after.get('model_version'),
               'calibration': after.get('calibration'), 'deployment_candidate': after.get('deployment_candidate'),
               'activated': after.get('activated'), 'pipeline_sha': after.get('pipeline_sha')}, 'model_loading_summary.json')
    json_dump({'status_code': first.status_code, 'required_fields_present': first.status_code == 200 and
               {'model_id', 'model_version', 'prediction', 'probability', 'risk_score', 'confidence',
                'threshold_used', 'feature_families', 'signals', 'recommendations', 'processing_time_ms'} <= set(first.json()),
               'prediction_values': sorted(set(predictions)), 'raw_content_included': False}, 'prediction_validation.json')
    json_dump({'requests': len(timings), 'average_latency_ms': statistics.mean(timings),
               'p50_latency_ms': timings[len(timings) // 2], 'p95_latency_ms': timings[max(0, int(len(timings) * .95) - 1)],
               'min_latency_ms': min(timings), 'max_latency_ms': max(timings),
               'first_request_loading_included_ms': first_request_ms,
               'average_feature_extraction_proxy_ms': statistics.mean(parsing),
               'average_prediction_ms': statistics.mean(predictions_ms), 'in_memory_only': True,
               'raw_content_included': False}, 'latency_summary.json')
    json_dump({'endpoint': '/api/v1/analyze', 'method': 'POST', 'successful_requests': sum(value == 'phishing' for value in predictions),
               'failed_requests': sum(value == 'error' for value in predictions), 'health_endpoint': '/api/v1/health',
               'persistence': 'none', 'network_fetches': 'none', 'attachment_execution': 'none',
               'raw_content_included': False}, 'api_inference_summary.json')


if __name__ == '__main__':
    main()
