"""Mode-aware analysis and metadata-only attachment safety tests."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.analysis_pipeline import pipeline
from app.services.email_parser import MAX_EMAIL_SIZE_BYTES


client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_ml_service():
    pipeline._ml_service = None  # type: ignore[protected-access]
    with patch('app.services.analysis_pipeline.LocalInferenceService') as mock_class:
        service = mock_class.return_value
        service.predict.return_value = MagicMock(
            predicted_label='legitimate',
            phishing_probability=0.1,
            legitimate_probability=0.9,
        )
        service.model_version = 'test-v1'
        yield
    pipeline._ml_service = None  # type: ignore[protected-access]


def test_quick_paste_legitimate_skips_unavailable_header_checks():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'sender_email': 'alice@example.com',
        'subject': 'Project update',
        'body': 'The project meeting is tomorrow at 10. Thank you.',
    })
    assert response.status_code == 200
    data = response.json()
    codes = {signal['code'] for signal in data['rule_analysis']['signals']}
    assert not any(code.startswith('header_') for code in codes)
    assert data['rule_analysis']['risk_score'] < 30


def test_quick_paste_preserves_typed_fields_and_attachment_metadata():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'sender_name': 'Support Team',
        'sender_email': 'support@example.com',
        'recipient_name': 'Customer',
        'recipient_email': 'customer@example.com',
        'reply_to': 'help@example.com',
        'subject': 'Your support request',
        'body': 'We have resolved your request.',
        'attachments': [{'filename': 'resolution.pdf', 'content_type': 'application/pdf', 'size_bytes': 2048}],
    })
    assert response.status_code == 200
    parsed = response.json()['parser']
    assert parsed['sender'] == {'name': 'Support Team', 'address': 'support@example.com'}
    assert parsed['subject'] == 'Your support request'
    assert parsed['body_text'] == 'We have resolved your request.'
    assert parsed['recipients'][0]['address'] == 'customer@example.com'
    assert parsed['reply_to']['address'] == 'help@example.com'
    assert parsed['attachments'][0]['filename'] == 'resolution.pdf'
    assert parsed['attachments'][0]['extension'] == '.pdf'
    assert parsed['attachments'][0]['suspicious_extension'] is False


def test_quick_paste_sender_may_be_omitted_without_sender_or_header_penalty():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'body': 'A normal copied support update.',
    })
    assert response.status_code == 200
    data = response.json()
    assert data['parser']['sender'] is None
    assert not any(signal['code'].startswith('header_') for signal in data['rule_analysis']['signals'])


def test_quick_paste_blank_optional_fields_are_accepted():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste', 'sender_email': '', 'recipient_email': '', 'reply_to': '',
        'subject': '', 'body': 'Valid visible message body.',
    })
    assert response.status_code == 200


def test_quick_paste_invalid_sender_email_has_field_error():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste', 'sender_email': 'not-an-email', 'body': 'Hello.',
    })
    assert response.status_code == 422
    assert response.json()['detail'][0]['loc'][-1] == 'sender_email'


def test_quick_paste_invalid_recipient_email_has_field_error():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste', 'recipient_email': 'Nitin', 'body': 'Hello.',
    })
    assert response.status_code == 422
    assert response.json()['detail'][0]['loc'][-1] == 'recipient_email'


def test_same_sender_and_recipient_is_zero_point_safe_context():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'sender_email': 'USER@EXAMPLE.COM',
        'recipient_email': 'user@example.com',
        'body': 'This is a normal self-sent test email.',
    })
    assert response.status_code == 200
    data = response.json()
    finding = next(signal for signal in data['rule_analysis']['signals'] if signal['code'] == 'SELF_ADDRESSED_EMAIL')
    assert finding == {
        'code': 'SELF_ADDRESSED_EMAIL',
        'category': 'metadata',
        'severity': 'low',
        'title': 'Sender and recipient are the same',
        'description': (
            'The message appears to have been sent to the same address it originated from. '
            'This can be legitimate, such as a self-sent or test email.'
        ),
        'score': 0,
        'evidence': 'user@example.com',
    }
    assert finding['score'] <= 5
    assert data['rule_analysis']['risk_score'] == 0
    assert data['rule_analysis']['classification'] == 'safe'
    assert data['decision']['classification'] == 'safe'


@pytest.mark.parametrize('payload', [
    {'sender_email': 'sender@example.com', 'recipient_email': 'other@example.com'},
    {'recipient_email': 'recipient@example.com'},
    {'sender_email': 'sender@example.com'},
])
def test_self_address_context_requires_matching_present_addresses(payload: dict[str, str]):
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste', 'body': 'Normal message.', **payload,
    })
    assert response.status_code == 200
    assert 'SELF_ADDRESSED_EMAIL' not in {
        signal['code'] for signal in response.json()['rule_analysis']['signals']
    }


def test_quick_paste_detects_credential_request_and_suspicious_url():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'subject': 'Verify your password immediately',
        'body': 'Confirm your password now at http://evil.example/login before access is suspended.',
    })
    assert response.status_code == 200
    codes = {signal['code'] for signal in response.json()['rule_analysis']['signals']}
    assert any(code.startswith('content_') for code in codes)
    assert any(code.startswith('url_') for code in codes)
    assert not any(code.startswith('header_') for code in codes)


def test_raw_email_still_runs_header_checks():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'raw_email',
        'raw_email': 'From: alice@example.com\nSubject: Hello\n\nNormal message.',
    })
    assert response.status_code == 200
    codes = {signal['code'] for signal in response.json()['rule_analysis']['signals']}
    assert 'header_missing_message_id' in codes


def test_raw_email_preserves_subject_and_message_id():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'raw_email',
        'raw_email': 'From: alice@example.com\nSubject: Header subject\nMessage-ID: <one@example.com>\n\nBody.',
    })
    assert response.status_code == 200
    parsed = response.json()['parser']
    assert parsed['subject'] == 'Header subject'
    assert parsed['message_id'] == '<one@example.com>'


@pytest.mark.parametrize('raw_email', [
    'mailed-by: gmail.com\nsigned-by: example.com\nsecurity: Standard encryption\nsubject: Copied subject\n\nVisible body',
    'This is only a plain body copied from an inbox.',
])
def test_raw_email_rejects_copied_display_text(raw_email: str):
    response = client.post('/api/v1/analysis/preview', json={'input_mode': 'raw_email', 'raw_email': raw_email})
    assert response.status_code == 400
    assert response.json()['detail'] == (
        "This looks like copied inbox text, not full email source. Use Quick Paste, or paste the message from "
        "'Show original' / 'View source'."
    )


def test_eml_upload_uses_full_parser_and_attachment_metadata():
    eml = (
        'From: sender@example.com\nSubject: Invoice\nMIME-Version: 1.0\n'
        'Content-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain\n\nSee invoice.\n'
        '--x\nContent-Type: application/pdf\nContent-Disposition: attachment; filename="invoice.pdf"\n\nPDF\n--x--'
    )
    response = client.post('/api/v1/analysis/preview', json={'input_mode': 'eml_upload', 'raw_email': eml})
    assert response.status_code == 200
    data = response.json()
    assert data['parser']['subject'] == 'Invoice'
    assert data['parser']['attachments'][0]['filename'] == 'invoice.pdf'
    assert any(signal['code'].startswith('header_') for signal in data['rule_analysis']['signals'])


def test_invalid_eml_structure_has_specific_error():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'eml_upload', 'raw_email': 'This is not an RFC822 message.',
    })
    assert response.status_code == 400
    assert response.json()['detail'] == 'The .eml file does not contain a valid RFC822 message structure.'


@pytest.mark.parametrize(('filename', 'flagged'), [('payload.exe', True), ('report.docm', True), ('report.pdf', False)])
def test_attachment_extension_metadata(filename: str, flagged: bool):
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'body': 'Please review the attached document.',
        'attachments': [{'filename': filename, 'content_type': 'application/octet-stream', 'size_bytes': 1200}],
    })
    assert response.status_code == 200
    codes = {signal['code'] for signal in response.json()['rule_analysis']['signals']}
    assert ('attachment_risky_extension' in codes) is flagged


def test_input_mode_validation():
    assert client.post('/api/v1/analysis/preview', json={'input_mode': 'unknown', 'body': 'hello'}).status_code == 422
    assert client.post('/api/v1/analysis/preview', json={'input_mode': 'quick_paste', 'body': ''}).status_code == 422


def test_two_megabyte_limit():
    response = client.post('/api/v1/analysis/preview', json={
        'input_mode': 'quick_paste',
        'body': 'x' * (MAX_EMAIL_SIZE_BYTES + 1),
    })
    assert response.status_code == 400


def test_analysis_does_not_write_files_or_open_network_connections():
    with (
        patch('pathlib.Path.write_text') as write_text,
        patch('pathlib.Path.write_bytes') as write_bytes,
        patch('socket.create_connection') as connect,
    ):
        response = client.post('/api/v1/analysis/preview', json={
            'input_mode': 'quick_paste',
            'body': 'A metadata-only message with report.pdf attached.',
            'attachments': [{'filename': 'report.pdf', 'content_type': 'application/pdf', 'size_bytes': 12}],
        })
    assert response.status_code == 200
    write_text.assert_not_called()
    write_bytes.assert_not_called()
    connect.assert_not_called()
