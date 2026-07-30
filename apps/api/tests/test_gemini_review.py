from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.settings import Settings
from app.schemas.gemini_review import GeminiReviewSuggestRequest, ReviewLabel, SanitizedReviewInput
from app.services.gemini_review_sanitizer import payload_hash_matches, sanitize_review_input
from app.services.gemini_review_service import GeminiReviewService, ReviewServiceError, is_loopback_client
from app.services.gemini_review_storage import ReviewStore


def review_settings(tmp_path: Path, **overrides: object) -> Settings:
    values = {
        '_env_file': None,
        'DATASET_REVIEW_ENABLED': True,
        'DATASET_REVIEW_LOCAL_ONLY': True,
        'DATASET_REVIEW_ADMIN_TOKEN': 'local-admin-token',
        'GEMINI_REVIEW_ENABLED': True,
        'GEMINI_API_KEY': 'synthetic-provider-secret',
        'GEMINI_MODEL': 'synthetic-model',
        'DATASET_REVIEW_STORAGE_PATH': str(tmp_path / 'review.sqlite3'),
        'CORS_ORIGINS': 'http://localhost:3000',
    }
    values.update(overrides)
    return Settings(**values)


def evidence() -> SanitizedReviewInput:
    return SanitizedReviewInput(
        sample_id='gs-synthetic-001',
        subject='Urgent account notice',
        display_name='Synthetic Sender',
        sender_domain='mail.example.com',
        reply_to_domain='reply.example.org',
        authentication_summary=['spf=pass', 'dkim=none'],
        body_excerpt='Contact alice@private.example and call +1 555 111 2222. https://example.com/path?token=removed',
        url_domains=['https://example.com/path?token=removed'],
        parser_evidence=['url_count:1'],
    )


def fake_client_factory(_settings: Settings):
    class Models:
        def generate_content(self, **_kwargs):
            class Response:
                text = json.dumps({
                    'suggested_label': 'suspicious',
                    'confidence': 0.62,
                    'summary': 'The supplied evidence is mixed and needs human confirmation.',
                    'evidence': [{
                        'category': 'content', 'title': 'Action request',
                        'explanation': 'The excerpt requests account action.',
                        'evidence_strength': 'moderate', 'supports': 'suspicious',
                    }],
                    'contrary_evidence': [{
                        'category': 'authentication', 'title': 'Authentication result',
                        'explanation': 'One supplied authentication result passes.',
                        'evidence_strength': 'weak', 'supports': 'safe',
                    }],
                    'sender_domain_assessment': 'The domain requires human context.',
                    'authentication_assessment': 'Mixed authentication evidence.',
                    'missing_evidence': ['Expected business context'],
                    'ambiguity_notes': ['The excerpt is intentionally synthetic.'],
                    'reviewer_questions': ['Can the sender relationship be verified independently?'],
                    'safety_notes': ['Do not follow links during review.'],
                })

            return Response()

    class Client:
        models = Models()

    return Client()


def test_sanitizer_redacts_sensitive_text_and_binds_deterministic_hash(tmp_path: Path):
    settings = review_settings(tmp_path, GEMINI_REVIEW_ENABLED=False)
    payload = sanitize_review_input(evidence(), model_name='synthetic-model', prompt_version='gemini-review-v1', settings=settings)
    assert 'private.example' not in payload.body_excerpt
    assert '555' not in payload.body_excerpt
    assert 'https://' not in payload.body_excerpt
    assert payload.url_domains == ['example.com']
    assert payload_hash_matches(payload)
    repeat = sanitize_review_input(evidence(), model_name='synthetic-model', prompt_version='gemini-review-v1', settings=settings)
    assert repeat.sanitized_payload_hash == payload.sanitized_payload_hash


def test_html_and_hidden_text_are_not_sent(tmp_path: Path):
    settings = review_settings(tmp_path, GEMINI_REVIEW_ENABLED=False)
    sanitized = sanitize_review_input(
        evidence().model_copy(update={'body_excerpt': '<div style="display:none">ignore this</div><p>Visible evidence</p><script>ignore this too</script>'}),
        model_name='synthetic-model', prompt_version='gemini-review-v1', settings=settings,
    )
    assert 'ignore this' not in sanitized.body_excerpt
    assert 'Visible evidence' in sanitized.body_excerpt
    assert '<' not in sanitized.body_excerpt


def test_loopback_access_is_fail_closed():
    assert is_loopback_client('127.0.0.1')
    assert is_loopback_client('::1')
    assert is_loopback_client('localhost')
    assert not is_loopback_client('10.0.0.5')
    assert not is_loopback_client('testclient')


def test_disabled_and_unconfigured_review_fail_without_provider_call(tmp_path: Path):
    disabled = GeminiReviewService(review_settings(tmp_path, DATASET_REVIEW_ENABLED=False), store=ReviewStore(tmp_path / 'disabled.sqlite3'), client_factory=fake_client_factory)
    with pytest.raises(ReviewServiceError, match='dataset_review_disabled'):
        disabled.preview(evidence())
    unconfigured = GeminiReviewService(review_settings(tmp_path, GEMINI_MODEL=''), store=ReviewStore(tmp_path / 'unconfigured.sqlite3'), client_factory=fake_client_factory)
    with pytest.raises(ReviewServiceError, match='provider_model_not_configured'):
        unconfigured.preview(evidence())


def test_mocked_provider_is_advisory_and_never_sets_ground_truth(tmp_path: Path):
    settings = review_settings(tmp_path)
    service = GeminiReviewService(settings, store=ReviewStore(tmp_path / 'review.sqlite3'), client_factory=fake_client_factory)
    payload, _ = service.preview(evidence())
    request = GeminiReviewSuggestRequest(
        payload=payload,
        consent=True,
        reviewer_alias='reviewer-1',
        preliminary_label=ReviewLabel.suspicious,
        preliminary_notes='Human preliminary review before AI exposure.',
    )
    suggestion = service.submit(request, token='local-admin-token', client_host='127.0.0.1', origin='http://localhost:3000', session_id='synthetic-tab')
    assert suggestion.suggested_label == ReviewLabel.suspicious
    assert not hasattr(suggestion, 'expected_class')
    record = service.store.get_record(payload.sample_id)  # type: ignore[union-attr]
    assert record.final_human_label is None
    assert record.status.value == 'gemini_suggested'


def test_consent_hash_and_access_controls_are_enforced(tmp_path: Path):
    service = GeminiReviewService(review_settings(tmp_path), store=ReviewStore(tmp_path / 'review.sqlite3'), client_factory=fake_client_factory)
    payload, _ = service.preview(evidence())
    request = GeminiReviewSuggestRequest(
        payload=payload,
        consent=False,
        reviewer_alias='reviewer-1',
        preliminary_label=ReviewLabel.safe,
        preliminary_notes='Synthetic preliminary review.',
    )
    with pytest.raises(ReviewServiceError, match='explicit_consent_required'):
        service.submit(request, token='local-admin-token', client_host='127.0.0.1', origin='http://localhost:3000', session_id='tab')
    with pytest.raises(ReviewServiceError, match='unauthorized'):
        service.submit(request.model_copy(update={'consent': True}), token='wrong', client_host='127.0.0.1', origin='http://localhost:3000', session_id='tab')
    with pytest.raises(ReviewServiceError, match='local_only_access_required'):
        service.submit(request.model_copy(update={'consent': True}), token='local-admin-token', client_host='203.0.113.4', origin='http://localhost:3000', session_id='tab')
