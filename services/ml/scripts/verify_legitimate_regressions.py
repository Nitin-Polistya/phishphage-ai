"""Run the five sanitized hard-negative fixtures through the real API and model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for path in (PROJECT_ROOT / 'apps' / 'api', PROJECT_ROOT / 'services' / 'ml' / 'src'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.main import app
from app.services.analysis_pipeline import pipeline


FIXTURE_DIR = PROJECT_ROOT / 'apps' / 'api' / 'tests' / 'fixtures' / 'legitimate_regression'
RULE_VERSION = 'rules-v3.1.0'
MODEL_VERSION = 'ml-english-template-robust-v3.0.0'
FIXTURE_NAMES = (
    'cline_hubspot_newsletter.eml',
    'github_education_approval.eml',
    'gmail_inbox_welcome_missing_auth.eml',
    'openai_mandrill_subscription.eml',
    'unstop_moengage_promotion.eml',
)
FOLLOWUP_BEFORE = {
    'cline_hubspot_newsletter.eml': {'final': 'safe'},
    'github_education_approval.eml': {'final': 'safe'},
    'gmail_inbox_welcome_missing_auth.eml': {
        'rule_score': 5, 'ml_phishing_probability_observed': 0.569407, 'final': 'suspicious',
    },
    'openai_mandrill_subscription.eml': {'final': 'safe'},
    'unstop_moengage_promotion.eml': {'final': 'safe'},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--model-path', type=Path,
        default=PROJECT_ROOT / 'services' / 'ml' / 'models' / 'phishshield_model.joblib',
    )
    parser.add_argument(
        '--output', type=Path,
        default=PROJECT_ROOT / 'services' / 'ml' / 'reports' / 'legitimate_regression.json',
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    pipeline.model_path = args.model_path.resolve()
    pipeline.ml_required = True
    pipeline._ml_service = None  # type: ignore[protected-access]
    client = TestClient(app)
    rows = []
    failures = []

    for fixture_name in FIXTURE_NAMES:
        fixture = FIXTURE_DIR / fixture_name
        response = client.post('/api/v1/analysis/preview', json={
            'input_mode': 'raw_email',
            'raw_email': fixture.read_text(encoding='utf-8'),
        })
        if response.status_code != 200:
            failures.append(f'{fixture.name}: HTTP {response.status_code}')
            continue
        data = response.json()
        row = {
            'fixture': fixture.name,
            'expected': 'safe',
            'rule_classification': data['rule_analysis']['classification'],
            'rule_raw_score': data['rule_raw_score'],
            'rule_adjusted_score': data['rule_adjusted_score'],
            'rule_signals': [signal['code'] for signal in data['rule_analysis']['signals']],
            'ml_status': data['ml_analysis']['status'],
            'ml_prediction': data['ml_prediction'],
            'ml_phishing_probability': round(float(data['ml_phishing_probability']), 6),
            'ml_threshold': data['ml_threshold'],
            'final_classification': data['decision']['classification'],
            'final_risk_score': data['decision']['risk_score'],
            'final_decision_confidence': data['final_decision_confidence'],
            'rule_ml_agreement': data['rule_ml_agreement'],
            'fusion_reason': data['fusion_reason'],
            'analysis_completeness': data['analysis_completeness']['state'],
            'limited_evidence': data['analysis_completeness']['limited_evidence'],
            'limited_evidence_warning': data['analysis_completeness']['warning'],
            'authentication_evidence_status': data['authentication_evidence_status'],
            'analysis_freshness': data['analysis_freshness'],
            'stale_reason': data['stale_reason'],
            'rule_version': data['rule_analysis']['engine_version'],
            'ml_version': data['ml_analysis']['model_version'],
            'positive_authentication_evidence': data['positive_authentication_evidence'],
            'url_source_types': sorted({item['source_type'] for item in data['parser']['url_evidence']}),
        }
        rows.append(row)
        if row['final_classification'] != 'safe':
            failures.append(f"{fixture.name}: final={row['final_classification']}")
        if row['ml_status'] != 'available':
            failures.append(f'{fixture.name}: ML unavailable')
        if row['rule_version'] != RULE_VERSION or row['ml_version'] != MODEL_VERSION:
            failures.append(f'{fixture.name}: stale engine version')
        if row['analysis_freshness'] != 'current' or row['stale_reason'] is not None:
            failures.append(f'{fixture.name}: contradictory freshness metadata')
        if fixture.name == 'gmail_inbox_welcome_missing_auth.eml':
            if not row['limited_evidence'] or row['authentication_evidence_status'] != 'unavailable':
                failures.append(f'{fixture.name}: missing limited-authentication qualification')
            if row['rule_ml_agreement'] != 'disagreement':
                failures.append(f'{fixture.name}: expected rule/ML disagreement')

    payload = {
        'report_schema_version': '1.0',
        'raw_email_bodies_included': False,
        'fixtures_are_training_data': False,
        'required_rule_version': RULE_VERSION,
        'required_model_version': MODEL_VERSION,
        'followup_before': FOLLOWUP_BEFORE,
        'before_summary': {'safe': 4, 'suspicious': 1, 'phishing': 0},
        'after_summary': {
            verdict: sum(row['final_classification'] == verdict for row in rows)
            for verdict in ('safe', 'suspicious', 'phishing')
        },
        'passed': not failures and len(rows) == 5,
        'failures': failures,
        'results': rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps({
        'passed': payload['passed'],
        'before_summary': payload['before_summary'],
        'after_summary': payload['after_summary'],
        'versions': [RULE_VERSION, MODEL_VERSION],
        'output': str(args.output),
        'failures': failures,
    }, indent=2))
    return 0 if payload['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
