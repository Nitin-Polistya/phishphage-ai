import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MAX_QUICK_ATTACHMENTS,
  MAX_QUICK_ATTACHMENT_SIZE,
  clearSelectedAttachments,
  deriveAttachmentMetadata,
  mergeAttachmentSelection,
  removeSelectedAttachment,
  toAttachmentMetadataPayload,
} from './attachment-metadata.ts';

function file(name, type, size, lastModified = 1) {
  return new File([new Uint8Array(size)], name, { type, lastModified });
}

test('derives PDF metadata from a File object', () => {
  const selected = deriveAttachmentMetadata(file('report.pdf', 'application/pdf', 128));
  assert.deepEqual(selected.metadata, {
    filename: 'report.pdf', content_type: 'application/pdf', size_bytes: 128,
    disposition: 'attachment', extension: '.pdf', suspicious_extension: false,
  });
});

test('derives ZIP metadata and marks the extension suspicious', () => {
  const selected = deriveAttachmentMetadata(file('archive.ZIP', 'application/zip', 64));
  assert.equal(selected.metadata.extension, '.zip');
  assert.equal(selected.metadata.suspicious_extension, true);
});

test('prevents duplicate filename, MIME type, and size combinations without reading file content', () => {
  const original = file('same.pdf', 'application/pdf', 5, 42);
  const first = mergeAttachmentSelection([], [original]);
  const duplicate = mergeAttachmentSelection(first.attachments, [original]);
  assert.equal(duplicate.attachments.length, 1);
  assert.match(duplicate.errors[0], /already selected/);
});

test('enforces maximum count, per-file size, and non-empty filename', () => {
  const files = Array.from({ length: MAX_QUICK_ATTACHMENTS + 1 }, (_, index) => file(`${index}.txt`, 'text/plain', 1, index));
  const countResult = mergeAttachmentSelection([], files);
  assert.equal(countResult.attachments.length, MAX_QUICK_ATTACHMENTS);
  assert.match(countResult.errors.at(-1) ?? '', /maximum/);

  const rejected = mergeAttachmentSelection([], [
    { name: 'large.bin', type: 'application/octet-stream', size: MAX_QUICK_ATTACHMENT_SIZE + 1, lastModified: 1 },
    { name: '   ', type: '', size: 1, lastModified: 2 },
  ]);
  assert.equal(rejected.attachments.length, 0);
  assert.equal(rejected.errors.length, 2);
});

test('removes a selected attachment', () => {
  const result = mergeAttachmentSelection([], [file('one.pdf', 'application/pdf', 1), file('two.pdf', 'application/pdf', 2)]);
  assert.deepEqual(removeSelectedAttachment(result.attachments, result.attachments[0].key).map((item) => item.metadata.filename), ['two.pdf']);
});

test('Clear and mode-switch reset helper removes all attachments', () => {
  const result = mergeAttachmentSelection([], [file('one.pdf', 'application/pdf', 1)]);
  assert.equal(result.attachments.length, 1);
  assert.deepEqual(clearSelectedAttachments(), []);
});

test('Quick Paste payload contains metadata only and never reads file contents', () => {
  const selected = deriveAttachmentMetadata(file('report.pdf', 'application/pdf', 12));
  const payload = toAttachmentMetadataPayload([selected]);
  assert.deepEqual(Object.keys(payload[0]).sort(), [
    'content_type', 'disposition', 'extension', 'filename', 'size_bytes', 'suspicious_extension',
  ]);
  assert.equal('text' in payload[0], false);
  assert.equal('arrayBuffer' in payload[0], false);
});
