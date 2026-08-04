from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from pathlib import Path

from app.schemas.gold_dataset import BatchImportFormat, BatchImportRequest, GoldReviewState
from app.services.gold_dataset_manager import GoldDatasetManager


HEADERS = [
    'source_sample_id', 'source_dataset', 'source_claimed_label', 'campaign_id', 'language',
    'subject', 'body_excerpt', 'sender_domain', 'reply_to_domain', 'authentication_summary',
    'url_domains', 'url_structural_flags', 'attachment_extension', 'attachment_mime',
    'normalized_content_hash', 'sample_hash',
]


def private_path(tmp_path: Path, name: str) -> Path:
    return tmp_path / 'repo' / 'services' / 'ml' / 'evaluation' / 'private' / name


def make_batch(label: str, count: int = 25) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=HEADERS, lineterminator='\n')
    writer.writeheader()
    for index in range(count):
        normalized = hashlib.sha256(f'{label}-rich-{index}'.encode()).hexdigest()
        sample_hash = hashlib.sha256(f'{label}-sample-{index}'.encode()).hexdigest()
        writer.writerow({
            'source_sample_id': f'{label}-rich-{index}',
            'source_dataset': 'fixture-rich-metadata',
            'source_claimed_label': label,
            'campaign_id': f'{label}-campaign-{index}',
            'language': 'en',
            'subject': f'Sanitized {label} notice {index}',
            'body_excerpt': f'Sanitized review evidence for candidate {index}.',
            'sender_domain': 'sender-placeholder.example',
            'reply_to_domain': '',
            'authentication_summary': 'spf=pass;dkim=fail' if label == 'phishing' else '',
            'url_domains': 'url-domain-placeholder' if label == 'phishing' else '',
            'url_structural_flags': 'sender_domain_mismatch' if label == 'phishing' else '',
            'attachment_extension': '.pdf' if label == 'phishing' and index < 3 else '',
            'attachment_mime': 'application/pdf' if label == 'phishing' and index < 3 else '',
            'normalized_content_hash': normalized,
            'sample_hash': sample_hash,
        })
    return output.getvalue()


def test_rich_metadata_batches_are_importer_compatible_without_approvals(tmp_path: Path):
    db_path = private_path(tmp_path, 'rich-pilot.sqlite3')
    manager = GoldDatasetManager(db_path)
    safe = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=make_batch('safe'), imported_by='phase-ivb-test', batch_id='rich-safe-test'))
    phishing = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=make_batch('phishing'), imported_by='phase-ivb-test', batch_id='rich-phishing-test'))

    assert safe.imported_count == phishing.imported_count == 25
    assert safe.duplicate_count == phishing.duplicate_count == 0
    assert all(item.state == GoldReviewState.pending for item in [*safe.items, *phishing.items])
    assert all(item.current_human_label is None for item in [*safe.items, *phishing.items])

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM gold_reviews WHERE state='approved'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM gold_review_audit WHERE new_state='approved'").fetchone()[0] == 0


def test_rich_metadata_header_rejects_unsupported_field(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'unsupported.sqlite3'))
    content = 'unsupported_field,source_sample_id\nvalue,safe-1\n'
    try:
        manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=content, imported_by='phase-ivb-test'))
    except Exception as error:
        assert 'unsupported' in str(error).lower()
    else:
        raise AssertionError('unsupported field was accepted')
