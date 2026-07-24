from typing import Mapping
from app.analyzers.feature_engineering import extract_features
from app.schemas.email import EmailAddress, EmailAttachmentMetadata, EmailHtmlLink, ParsedEmail


def email(
    subject: str | None = None,
    body: str = "",
    sender: str = "notice@uorak.com",
    reply_to: str | None = None,
    urls: list[str] | None = None,
    headers: dict[str, str] | None = None,
    attachments: list[EmailAttachmentMetadata] | None = None,
    links: list[EmailHtmlLink] | None = None,
) -> ParsedEmail:
    resolved_urls: list[str] = [] if urls is None else list(urls)
    resolved_headers: dict[str, str] = {} if headers is None else dict(headers)
    resolved_attachments: list[EmailAttachmentMetadata] = [] if attachments is None else list(attachments)
    resolved_links: list[EmailHtmlLink] = [] if links is None else list(links)

    return ParsedEmail(
        subject=subject,
        body_text=body,
        sender=EmailAddress(address=sender) if sender else None,
        reply_to=EmailAddress(address=reply_to) if reply_to else None,
        extracted_urls=resolved_urls,
        headers=resolved_headers,
        attachments=resolved_attachments,
        html_links=resolved_links,
    )


def _int_feature(features: Mapping[str, int | float | str], key: str) -> int:
    value = features[key]
    assert isinstance(value, int)
    return value




def test_government_impersonation_and_domain_consistency_features():
    features, explanations, evidence = extract_features(email(
        'Brazilian Labor Court summons',
        'The ministry court requires an urgent response to this tax notice.',
        urls=['https://conteudo-protegido.one/case?id=1'],
    ))
    assert features['government_claim'] == 1
    assert features['government_domain_mismatch'] == 1
    assert features['government_link_domain_mismatch'] == 1
    assert features['url_domain_different_organization'] == 1
    assert explanations['government_domain_mismatch']
    assert evidence['government_domain_mismatch'] == 'uorak.com'


def test_bank_delivery_and_technology_claims_are_binary_or_counts():
    features, _, _ = extract_features(email(
        'Microsoft delivery payment',
        'PayPal bank payment and DHL delivery notification from Microsoft.',
        sender='alerts@example.com',
    ))
    assert features['financial_claim'] == 1
    assert features['delivery_claim'] == 1
    assert features['technology_claim'] == 1
    assert _int_feature(features, 'organization_claim_count') >= 3
    assert all(isinstance(value, (int, float, str)) for value in features.values())


def test_benign_official_government_newsletter_has_no_domain_mismatch():
    features, _, _ = extract_features(email(
        'Ministry newsletter', 'The ministry publishes its monthly public newsletter.',
        sender='news@agency.gov.br', urls=['https://agency.gov.br/news'],
    ))
    assert features['government_claim'] == 1
    assert features['official_sender_domain'] == 1
    assert features['official_link_domain'] == 1
    assert 'government_domain_mismatch' not in features


def test_authentication_and_provider_headers_are_structured_without_decision_logic():
    features, explanations, _ = extract_features(email(
        'Notice', 'Review this message.', headers={
            'Authentication-Results': 'mx; spf=fail; dkim=pass; dmarc=quarantine; compauth=fail',
            'X-MS-Exchange-Organization-SCL': '5',
            'X-MS-Exchange-Organization-PCL': '3',
            'X-MS-Exchange-Organization-BCL': '2',
            'SpamVerdict': 'spam',
        },
    ))
    assert features['spf_fail'] == 1
    assert features['dkim_pass'] == 1
    assert features['dmarc_quarantine'] == 1
    assert features['compauth_failed'] == 1
    assert features['provider_scl'] == 5.0
    assert features['provider_pcl'] == 3.0
    assert features['provider_bcl'] == 2.0
    assert features['provider_spam_verdict_spam'] == 1
    assert explanations['compauth_failed']


def test_attachment_features_use_metadata_only():
    features, _, _ = extract_features(email(
        'Documents', 'Please review.', attachments=[
            EmailAttachmentMetadata(filename='court_summons.pdf.exe', content_type='application/octet-stream', size_bytes=10),
            EmailAttachmentMetadata(filename='tax_invoice.xlsm', content_type='application/vnd.ms-excel.sheet.macroEnabled.12', size_bytes=20),
        ],
    ))
    assert features['attachment_count'] == 2
    assert features['macro_document'] == 1
    assert features['double_extension'] == 1
    assert features['court_document_filename'] == 1
    assert features['tax_document_filename'] == 1
    assert features['invoice_like_filename'] == 1


def test_url_features_cover_domains_queries_tracking_and_visible_text():
    features, _, _ = extract_features(email(
        'Update', 'Open the link.', sender='sender@example.com',
        urls=['https://paypal-security.xyz/a/b/c?utm_source=x&long=' + 'x' * 90, 'https://xn--paypal-3ve.example/login'],
        links=[EmailHtmlLink(visible_text='https://example.com', href='https://evil.xyz/login', visible_domain='example.com', href_domain='evil.xyz', domain_mismatch=True)],
    ))
    assert features['number_of_domains'] == 2
    assert features['number_of_unique_domains'] == 2
    assert features['url_depth'] == 3
    assert features['tracking_parameters'] == 1
    assert features['long_query'] == 1
    assert features['punycode'] == 1
    assert features['suspicious_tld'] == 1
    assert features['link_text_domain_mismatch'] == 1
    assert features['lookalike_domain'] == 2


def test_legal_and_tax_features_have_explanations_and_benign_text_does_not_crash():
    features, explanations, evidence = extract_features(email(
        'Tax notice', 'A lawsuit summons and case number require legal action. A penalty and fine may follow.',
        sender='notice@example.com',
    ))
    for name in ('legal_lawsuit', 'legal_summons', 'legal_case_number', 'legal_action', 'legal_penalty', 'legal_fine', 'tax_notice'):
        assert _int_feature(features, name) >= 1
        assert explanations[name]
        assert evidence[name]
    safe_features, _, _ = extract_features(email('Microsoft update', 'Your Microsoft notification is ready.', sender='updates@microsoft.com'))
    assert safe_features['technology_claim'] == 1
    assert 'government_domain_mismatch' not in safe_features
