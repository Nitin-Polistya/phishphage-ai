import assert from 'node:assert/strict';
import test from 'node:test';

import { buildContentSecurityPolicy } from './security-policy.ts';

const apiOrigin = 'http://127.0.0.1:8000';
const requiredDirectives = [
  "default-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  'img-src \'self\' data:',
  'font-src \'self\' data:',
  `connect-src 'self' ${apiOrigin}`,
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
];

test('development CSP allows React Refresh eval while preserving the API origin', () => {
  const policy = buildContentSecurityPolicy(apiOrigin, true);

  assert.match(policy, /script-src 'self' 'unsafe-inline' 'unsafe-eval'/);
  for (const directive of requiredDirectives) assert.match(policy, new RegExp(directive.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('production CSP excludes unsafe-eval and preserves restrictive directives', () => {
  const policy = buildContentSecurityPolicy(apiOrigin, false);

  assert.match(policy, /script-src 'self' 'unsafe-inline'(?:;|$)/);
  assert.doesNotMatch(policy, /'unsafe-eval'/);
  for (const directive of requiredDirectives) assert.match(policy, new RegExp(directive.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});
