const { test } = require('node:test');
const assert = require('node:assert');
const { checkHeaders } = require('../server/services/headerCheck');

test('flags missing HSTS header', () => {
  const { results } = checkHeaders({});
  const hsts = results.find((r) => r.id === 'strict-transport-security');
  assert.strictEqual(hsts.pass, false);
});

test('passes HSTS with sufficient max-age', () => {
  const { results } = checkHeaders({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' });
  const hsts = results.find((r) => r.id === 'strict-transport-security');
  assert.strictEqual(hsts.pass, true);
});

test('flags HSTS with too-short max-age', () => {
  const { results } = checkHeaders({ 'strict-transport-security': 'max-age=100' });
  const hsts = results.find((r) => r.id === 'strict-transport-security');
  assert.strictEqual(hsts.pass, false);
});

test('flags CSP with unsafe-inline as a weakened pass', () => {
  const { results } = checkHeaders({ 'content-security-policy': "script-src 'unsafe-inline'" });
  const csp = results.find((r) => r.id === 'content-security-policy');
  assert.strictEqual(csp.pass, false);
});

test('passes clean CSP', () => {
  const { results } = checkHeaders({ 'content-security-policy': "script-src 'self'" });
  const csp = results.find((r) => r.id === 'content-security-policy');
  assert.strictEqual(csp.pass, true);
});

test('passCount reflects number of passing checks', () => {
  const { passCount, total } = checkHeaders({
    'strict-transport-security': 'max-age=31536000',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  });
  assert.strictEqual(total, 6);
  assert.strictEqual(passCount, 3);
});
