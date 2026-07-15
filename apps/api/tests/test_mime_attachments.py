"""Safe MIME attachment metadata extraction regression tests."""

from email.message import EmailMessage
from email.policy import default

from app.services.email_parser import parse_email


def base_message() -> EmailMessage:
    message = EmailMessage()
    message['From'] = 'sender@example.com'
    message['To'] = 'recipient@example.com'
    message['Subject'] = 'Attachment test'
    message['Message-ID'] = '<attachments@example.com>'
    message.set_content('Visible message body.')
    return message


def test_pdf_and_zip_attachments_include_size_and_risk_status():
    message = base_message()
    message.add_attachment(b'%PDF-safe', maintype='application', subtype='pdf', filename='report.pdf')
    message.add_attachment(b'PK-safe', maintype='application', subtype='zip', filename='archive.zip')
    attachments = parse_email(message.as_string(policy=default)).attachments
    assert [(item.filename, item.size_bytes) for item in attachments] == [('report.pdf', 9), ('archive.zip', 7)]
    assert attachments[0].extension == '.pdf' and not attachments[0].suspicious_extension
    assert attachments[1].extension == '.zip' and attachments[1].suspicious_extension


def test_encoded_mime_filename_is_decoded():
    raw = (
        'From: sender@example.com\nTo: recipient@example.com\nSubject: Encoded\nMIME-Version: 1.0\n'
        'Content-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain\n\nBody\n'
        '--x\nContent-Type: application/pdf\nContent-Disposition: attachment; '
        'filename="=?utf-8?b?csOpc3Vtw6kucGRm?="\nContent-Transfer-Encoding: base64\n\nUERG\n--x--\n'
    )
    attachment = parse_email(raw).attachments[0]
    assert attachment.filename == 'résumé.pdf'
    assert attachment.extension == '.pdf'


def test_inline_image_with_filename_is_attachment_not_body():
    message = base_message()
    message.add_attachment(b'image-bytes', maintype='image', subtype='png', filename='logo.png', disposition='inline')
    parsed = parse_email(message.as_string(policy=default))
    assert parsed.attachments[0].filename == 'logo.png'
    assert parsed.attachments[0].disposition == 'inline'
    assert 'image-bytes' not in parsed.body_text


def test_nested_multipart_alternative_inside_mixed():
    message = base_message()
    message.add_alternative('<p>Visible message body.</p>', subtype='html')
    message.add_attachment(b'document', maintype='application', subtype='pdf', filename='nested.pdf')
    parsed = parse_email(message.as_string(policy=default))
    assert [item.filename for item in parsed.attachments] == ['nested.pdf']
    assert 'Visible message body.' in parsed.body_text


def test_attachment_without_filename_is_preserved():
    message = base_message()
    message.add_attachment(b'unknown', maintype='application', subtype='octet-stream')
    attachment = parse_email(message.as_string(policy=default)).attachments[0]
    assert attachment.filename is None
    assert attachment.content_type == 'application/octet-stream'
    assert attachment.disposition == 'attachment'


def test_content_type_name_parameter_without_disposition_is_preserved():
    raw = (
        'From: sender@example.com\nTo: recipient@example.com\nSubject: Named part\nMIME-Version: 1.0\n'
        'Content-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain\n\nBody\n'
        '--x\nContent-Type: application/pdf; name="named.pdf"\nContent-Transfer-Encoding: base64\n\nUERG\n--x--\n'
    )
    assert parse_email(raw).attachments[0].filename == 'named.pdf'


def test_message_with_no_attachments():
    assert parse_email(base_message().as_string(policy=default)).attachments == []


def test_multiple_attachments_are_all_preserved():
    message = base_message()
    for name in ('one.pdf', 'two.txt', 'three.jpg'):
        message.add_attachment(name.encode(), maintype='application', subtype='octet-stream', filename=name)
    assert [item.filename for item in parse_email(message.as_string(policy=default)).attachments] == [
        'one.pdf', 'two.txt', 'three.jpg'
    ]
