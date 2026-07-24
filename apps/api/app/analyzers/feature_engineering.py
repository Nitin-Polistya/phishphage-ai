"""Deterministic feature extraction; observations only, never scoring."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from app.schemas.email import ParsedEmail
from app.services.domain_utils import domains_align, registrable_domain

ORGANIZATION_GROUPS: dict[str, tuple[str, ...]] = {
    'government': ('court', 'tribunal', 'ministry', 'police', 'tax', 'customs', 'passport', 'immigration', 'government', 'labor', 'labour'),
    'financial': ('bank', 'payment', 'mastercard', 'visa', 'paypal'),
    'technology': ('microsoft', 'google', 'apple', 'amazon'),
    'delivery': ('dhl', 'fedex', 'ups', 'usps'),
}
BRAND_KEYWORDS = ('amazon', 'apple', 'dhl', 'fedex', 'google', 'mastercard', 'microsoft', 'paypal', 'ups', 'usps', 'visa')
OFFICIAL_SUFFIXES = ('.gov', '.gov.in', '.gov.uk', '.jus.br', '.gov.br', '.mil', '.edu')
SUSPICIOUS_TLDS = {'.xyz', '.top', '.click', '.link', '.live', '.today', '.online', '.site', '.one', '.work', '.icu', '.shop', '.win', '.loan', '.zip', '.mov'}
TRACKING_PARAMETERS = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'gclid', 'fbclid', 'mc_cid', 'mc_eid', 'msclkid'}
CONTENT_PATTERNS = {
    'legal_lawsuit': r'\blawsuit\b', 'legal_court': r'\bcourt\b', 'legal_legal': r'\blegal\b', 'legal_summons': r'\bsummons\b',
    'legal_case_number': r'\bcase\s*(?:number|no\.?|#)\b', 'legal_hearing': r'\bhearing\b',
    'legal_urgent_response': r'\b(?:urgent|immediately|within\s+\d+\s+days?)\b', 'legal_action': r'\blegal\s+action\b',
    'tax_notice': r'\btax\s+(?:notice|return|payment)\b', 'legal_penalty': r'\bpenalt(?:y|ies)\b',
    'legal_fine': r'\bfine\b', 'legal_warrant': r'\bwarrant\b', 'legal_subpoena': r'\bsubpoena\b',
    'authority_language': r'\b(?:official|authorized|mandatory|required|decree|directive|regulation)\b',
    'legal_pressure': r'\b(?:failure to comply|legal proceedings|court order|summons|non-compliance)\b',
    'account_language': r'\b(?:account\s+(?:locked|suspended|disabled|verify|update|security))\b',
    'credential_request': r'\b(?:password|login|credentials|secret|pin|ssn)\s+(?:verify|confirm|update|required)\b',
    'urgent_action': r'\b(?:act now|immediate action|urgent|time-sensitive|deadline|expiring)\b',
}


def _domain(value: str | None) -> str | None:
    if not value or '@' not in value:
        return None
    return value.rsplit('@', 1)[-1].strip().strip('<>').lower().rstrip('.')


def _official(domain: str | None) -> bool:
    return bool(domain and any(domain == suffix[1:] or domain.endswith(suffix) for suffix in OFFICIAL_SUFFIXES))


def _tld(domain: str) -> str:
    return '.' + domain.rsplit('.', 1)[-1].lower() if '.' in domain else ''


def _add(
    features: dict[str, int | float | str],
    explanations: dict[str, str],
    evidence: dict[str, str],
    name: str,
    value: int | float | str,
    explanation: str,
    observed: object,
) -> None:
    features[name] = value
    explanations[name] = explanation
    evidence[name] = str(observed)[:500]


def _provider_number(headers: dict[str, str], names: tuple[str, ...]) -> float | None:
    combined = ' '.join(f'{key}: {value}' for key, value in headers.items())
    pattern = rf'(?:{"|".join(re.escape(name) for name in names)})\s*[:=]\s*(-?\d+(?:\.\d+)?)'
    match = re.search(pattern, combined, re.IGNORECASE)
    return float(match.group(1)) if match else None


def _auth_status(headers: dict[str, str], mechanism: str) -> str:
    header = headers.get('authentication-results', '')
    if not header:
        return 'none'
    # Match mechanism=status or mechanism: status
    match = re.search(rf'\b{mechanism}\s*[=:]\s*([a-z]+)', header, re.IGNORECASE)
    return match.group(1).lower() if match else 'none'


def extract_features(email: ParsedEmail) -> tuple[dict[str, int | float | str], dict[str, str], dict[str, str]]:
    """Return feature values, explanations, and observed evidence."""
    features: dict[str, int | float | str] = {}
    explanations: dict[str, str] = {}
    evidence: dict[str, str] = {}
    text = ' '.join(filter(None, [email.subject, email.body_text, email.body_visible_text, email.sender.name if email.sender else None])).casefold()
    headers = {key.casefold().replace('_', '-'): value for key, value in (email.headers or {}).items()}
    
    sender_domain = _domain(str(email.sender.address) if email.sender else None)
    reply_domain = _domain(str(email.reply_to.address) if email.reply_to else None)
    return_path_domain = _domain(headers.get('return-path'))
    
    urls = list(email.extracted_urls or [])
    parsed_urls = [urlsplit(url if '://' in url else f'http://{url}') for url in urls]
    url_domains = [parsed.hostname.casefold().rstrip('.') for parsed in parsed_urls if parsed.hostname]
    unique_domains = sorted(set(url_domains))

    claims: dict[str, list[str]] = {group: sorted({term for term in terms if re.search(rf'\b{re.escape(term)}\b', text)}) for group, terms in ORGANIZATION_GROUPS.items()}
    for group, terms in claims.items():
        if terms:
            _add(features, explanations, evidence, f'{group}_claim', 1, f'The message references {group} organizations or terminology.', ', '.join(terms))
            _add(features, explanations, evidence, f'{group}_claim_count', len(terms), f'The message contains {len(terms)} distinct {group} organization terms.', ', '.join(terms))
    claimed_terms = [term for terms in claims.values() for term in terms]
    if claimed_terms:
        _add(features, explanations, evidence, 'organization_claim_count', len(claimed_terms), 'The message contains references to trusted-organization terminology.', ', '.join(claimed_terms))
    if claims.get('government'):
        _add(features, explanations, evidence, 'government_claim', 1, 'The message contains government-related terminology; this is an observed claim, not proof of impersonation.', ', '.join(claims['government']))

    if sender_domain:
        _add(features, explanations, evidence, 'official_sender_domain', int(_official(sender_domain)), 'The sender domain uses an official-style government, military, or education suffix when present.', sender_domain)
    official_links = [domain for domain in unique_domains if _official(domain)]
    if official_links:
        _add(features, explanations, evidence, 'official_link_domain', len(official_links), 'One or more extracted link domains use an official-style government, military, or education suffix.', ', '.join(official_links))
    if claims.get('government') and sender_domain and not _official(sender_domain):
        _add(features, explanations, evidence, 'government_domain_mismatch', 1, 'The email claims a government organization, but the sender domain is not an official-style government domain.', sender_domain)
    organization_tokens = set(claimed_terms)
    if sender_domain and organization_tokens:
        sender_base = registrable_domain(sender_domain) or sender_domain
        matching = [term for term in organization_tokens if term in sender_base]
        _add(features, explanations, evidence, 'sender_domain_partial_match' if matching else 'sender_domain_different_organization', 1, 'A claimed organization term appears in the sender domain.' if matching else 'The sender domain does not contain the organization terms observed in the message.', f'{sender_domain}: {", ".join(matching) or "no match"}')
    if reply_domain and sender_domain:
        _add(features, explanations, evidence, 'reply_to_domain_match', int(domains_align(sender_domain, reply_domain)), 'The Reply-To domain is compared with the visible sender domain.', f'sender={sender_domain}, reply_to={reply_domain}')
        if not domains_align(sender_domain, reply_domain):
            _add(features, explanations, evidence, 'reply_to_domain_mismatch', 1, 'The Reply-To domain differs from the visible sender domain.', f'sender={sender_domain}, reply_to={reply_domain}')
    
    if return_path_domain:
        _add(features, explanations, evidence, 'return_path_domain', 1, 'A Return-Path domain was observed.', return_path_domain)
        if sender_domain and not domains_align(sender_domain, return_path_domain):
            _add(features, explanations, evidence, 'from_return_path_mismatch', 1, 'The sender domain differs from the Return-Path domain.', f'from={sender_domain}, return_path={return_path_domain}')
    
    if sender_domain and return_path_domain and domains_align(sender_domain, return_path_domain):
         _add(features, explanations, evidence, 'from_return_path_match', 1, 'The sender domain matches the Return-Path domain.', f'from={sender_domain}, return_path={return_path_domain}')
    if unique_domains:
        matching_urls = [domain for domain in url_domains if sender_domain and domains_align(sender_domain, domain)]
        _add(features, explanations, evidence, 'url_domain_match_sender', int(bool(matching_urls)), 'At least one extracted link domain matches the visible sender domain.', ', '.join(matching_urls) or 'no matching link domain')
        if sender_domain and not matching_urls:
            _add(features, explanations, evidence, 'url_domain_different_organization', 1, 'Extracted link domains do not match the visible sender domain.', ', '.join(unique_domains))
        partial = [domain for domain in unique_domains if any(term in domain for term in organization_tokens)]
        if partial:
            _add(features, explanations, evidence, 'url_domain_partial_match', 1, 'A claimed organization term appears in an extracted link domain.', ', '.join(partial))
        if claims.get('government') and not official_links:
            _add(features, explanations, evidence, 'government_link_domain_mismatch', 1, 'The email claims a government organization, but its extracted links use non-official-style domains.', ', '.join(unique_domains))
    suspicious_domains = [domain for domain in unique_domains if _tld(domain) in SUSPICIOUS_TLDS]
    if suspicious_domains:
        _add(features, explanations, evidence, 'suspicious_tld', len(suspicious_domains), 'Extracted links use top-level domains commonly seen in disposable or deceptive infrastructure.', ', '.join(suspicious_domains))
    lookalikes = [domain for domain in unique_domains if any(brand in domain and not domain.startswith(brand + '.') for brand in BRAND_KEYWORDS)]
    if lookalikes:
        _add(features, explanations, evidence, 'lookalike_domain', len(lookalikes), 'An extracted domain contains a brand keyword without being that brand’s normal domain.', ', '.join(lookalikes))

    auth_header = headers.get('authentication-results', '')
    _add(features, explanations, evidence, 'authentication_results_present', int(bool(auth_header)), 'The Authentication-Results header is present.', 'Present' if auth_header else 'Absent')
    
    auth_allowed = {'spf': {'pass', 'fail', 'softfail', 'neutral', 'none'}, 'dkim': {'pass', 'fail', 'none'}, 'dmarc': {'pass', 'fail', 'quarantine', 'reject', 'none'}}
    fail_count = 0
    none_count = 0
    for mechanism, allowed in auth_allowed.items():
        status = _auth_status(headers, mechanism)
        if status not in allowed:
            status = 'none'
        _add(features, explanations, evidence, f'{mechanism}_{status}', 1, f'The Authentication-Results header reports {mechanism.upper()} as {status}.', f'{mechanism}={status}')
        if status == 'fail': fail_count += 1
        if status == 'none': none_count += 1
    
    _add(features, explanations, evidence, 'authentication_failure_count', fail_count, 'Count of failed authentication mechanisms (SPF, DKIM, DMARC).', f'fails={fail_count}')
    _add(features, explanations, evidence, 'authentication_none_count', none_count, 'Count of authentication mechanisms not present or set to none.', f'none={none_count}')
    compauth = re.search(r'\bcompauth\s*[=:]\s*([a-z]+)', headers.get('authentication-results', ''), re.IGNORECASE)
    if compauth:
        status = compauth.group(1).lower()
        _add(features, explanations, evidence, f'compauth_{status}', 1, f'The provider Authentication-Results header reports composite authentication as {status}.', f'compauth={status}')
        if status == 'fail':
            _add(features, explanations, evidence, 'compauth_failed', 1, 'The provider reports that composite authentication failed.', 'compauth=fail')

    for feature, names, explanation in (('provider_scl', ('scl', 'spamconfidencelevel'), 'A provider-generated Spam Confidence Level was present.'), ('provider_pcl', ('pcl',), 'A provider-generated Phishing Confidence Level was present.'), ('provider_bcl', ('bcl',), 'A provider-generated Bulk Complaint Level was present.'), ('provider_spam_confidence', ('spamconfidence', 'spam-confidence'), 'A provider-generated spam confidence value was present.')):
        number = _provider_number(headers, names)
        if number is not None:
            _add(features, explanations, evidence, feature, number, explanation, str(number))
    
    combined_headers = ' '.join(f'{k}: {v}' for k, v in headers.items()).casefold()
    verdict = re.search(r'\b(?:spamverdict|spam-verdict|spam verdict)\s*[:=]\s*([a-z_-]+)', combined_headers)
    if verdict:
        _add(features, explanations, evidence, 'provider_spam_verdict_present', 1, 'A provider-generated spam verdict was present in the message headers.', verdict.group(0))
        _add(features, explanations, evidence, f'provider_spam_verdict_{verdict.group(1)}', 1, 'The provider supplied a categorical spam verdict; it is exposed without changing the decision.', verdict.group(0))

    attachments = list(email.attachments or [])
    if attachments:
        extensions = [((item.extension or '').lower() or (item.filename or '').rsplit('.', 1)[-1].lower()) for item in attachments]
        names = [item.filename or '' for item in attachments]
        _add(features, explanations, evidence, 'attachment_count', len(attachments), 'The message contains attachment metadata records.', ', '.join(names))
        
        image_count = sum(1 for item in attachments if (item.content_type or '').lower().startswith('image/') or (item.extension or '').lower() in {'.jpg', '.jpeg', '.png', '.gif', '.webp'})
        _add(features, explanations, evidence, 'image_attachment_count', image_count, 'Number of image attachments detected.', str(image_count))
        
        archive_count = sum(1 for ext in extensions if ext in {'.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'})
        _add(features, explanations, evidence, 'archive_attachment_count', archive_count, 'Number of archive attachments detected.', str(archive_count))
        
        exec_count = sum(1 for ext in extensions if ext in {'.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.msi'})
        _add(features, explanations, evidence, 'executable_attachment_count', exec_count, 'Number of executable attachments detected.', str(exec_count))

        for extension in sorted({extension for extension in extensions if extension}):
            _add(features, explanations, evidence, f'attachment_extension_{extension.lstrip(".")}', extensions.count(extension), 'The message contains this attachment extension; file contents were not read.', extension)
        if archive_count > 0:
            _add(features, explanations, evidence, 'archive_present', 1, 'At least one attachment uses an archive-like extension.', ', '.join(extensions))
        if image_count == len(attachments) and len(attachments) > 0:
            _add(features, explanations, evidence, 'image_only_attachment', 1, 'All attachment metadata records identify image files.', ', '.join(extensions))
        if any(extension in {'.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppam', '.ppsm', '.sldm'} for extension in extensions):
            _add(features, explanations, evidence, 'macro_document', 1, 'At least one attachment extension permits Office macros.', ', '.join(extensions))
        if any(len(re.findall(r'\.', name)) >= 2 for name in names):
            _add(features, explanations, evidence, 'double_extension', 1, 'An attachment filename contains multiple extensions.', ', '.join(names))
        for feature, pattern, explanation in (('invoice_like_filename', r'invoice|receipt|bill|payment', 'An attachment filename resembles an invoice or payment document.'), ('court_document_filename', r'court|summons|subpoena|hearing|lawsuit', 'An attachment filename resembles a court or legal document.'), ('tax_document_filename', r'tax|irs|customs|vat|penalty', 'An attachment filename resembles a tax or customs document.')):
            matched = [name for name in names if re.search(pattern, name, re.IGNORECASE)]
            if matched:
                _add(features, explanations, evidence, feature, len(matched), explanation, ', '.join(matched))

    if urls:
        _add(features, explanations, evidence, 'number_of_domains', len(url_domains), 'The number of domains observed in extracted links.', ', '.join(unique_domains))
        _add(features, explanations, evidence, 'number_of_unique_domains', len(unique_domains), 'The number of distinct domains observed in extracted links.', ', '.join(unique_domains))
        mismatches = [link.href for link in email.html_links if link.domain_mismatch]
        if mismatches:
            _add(features, explanations, evidence, 'link_text_domain_mismatch', len(mismatches), 'Visible link text and the actual destination domain differ.', ', '.join(mismatches))
        government_domains = [domain for domain in unique_domains if any(term in domain for term in ORGANIZATION_GROUPS['government'])]
        if government_domains:
            _add(features, explanations, evidence, 'government_keyword_in_domain', len(government_domains), 'An extracted domain contains government-related terminology.', ', '.join(government_domains))
        brand_domains = [domain for domain in unique_domains if any(term in domain for term in BRAND_KEYWORDS)]
        if brand_domains:
            _add(features, explanations, evidence, 'brand_keyword_in_domain', len(brand_domains), 'An extracted domain contains a recognized organization keyword.', ', '.join(brand_domains))
        depths = [len([part for part in parsed.path.split('/') if part]) for parsed in parsed_urls]
        _add(features, explanations, evidence, 'url_depth', max(depths, default=0), 'The deepest extracted URL path contains this many non-empty segments.', str(max(depths, default=0)))
        long_queries = [url for url, parsed in zip(urls, parsed_urls) if len(parsed.query) > 80]
        if long_queries:
            _add(features, explanations, evidence, 'long_query', len(long_queries), 'Some extracted URLs contain unusually long query strings.', ', '.join(long_queries))
        tracked = [url for url, parsed in zip(urls, parsed_urls) if any(name in TRACKING_PARAMETERS for name, _ in parse_qsl(parsed.query, keep_blank_values=True))]
        if tracked:
            _add(features, explanations, evidence, 'tracking_parameters', len(tracked), 'Some extracted URLs contain common tracking parameters.', ', '.join(tracked))
        
        # Additional URL features
        non_https = [url for url in urls if not url.startswith('https://')]
        if non_https:
            _add(features, explanations, evidence, 'non_https_url_present', 1, 'One or more URLs use a non-HTTPS protocol.', ', '.join(non_https))
        
        ip_hosts = [parsed.hostname for parsed in parsed_urls if parsed.hostname and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.hostname)]
        if ip_hosts:
            _add(features, explanations, evidence, 'ip_host_present', len(ip_hosts), 'One or more links use an IP address as the host.', ', '.join(ip_hosts))
            
        shorteners = {'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly'}
        short_urls = [domain for domain in unique_domains if domain in shorteners]
        if short_urls:
            _add(features, explanations, evidence, 'shortened_url_present', len(short_urls), 'One or more shortened URLs were detected.', ', '.join(short_urls))
            
        unrelated = [domain for domain in unique_domains if sender_domain and not domains_align(sender_domain, domain)]
        if unrelated:
            _add(features, explanations, evidence, 'unrelated_link_domain_present', len(unrelated), 'Extracted link domains are unrelated to the sender domain.', ', '.join(unrelated))

        for name, domains, explanation in (('punycode', [domain for domain in unique_domains if 'xn--' in domain], 'An extracted domain uses Punycode encoding.'), ('recent_tld', [domain for domain in unique_domains if _tld(domain) in SUSPICIOUS_TLDS], 'An extracted domain uses a newer or frequently abused TLD.')):
            if domains:
                _add(features, explanations, evidence, name, len(domains), explanation, ', '.join(domains))

    for feature, pattern in CONTENT_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            label = feature.replace('_', ' ')
            _add(features, explanations, evidence, feature, len(matches), f'The message contains the pattern “{label}”.', ', '.join(matches[:5]))
    return features, explanations, evidence
