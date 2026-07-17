const { test } = require('node:test');
const assert = require('node:assert');
const { checkCookies } = require('../server/services/cookieCheck');

test('handles no cookies gracefully', () => {
  const result = checkCookies(undefined);
  assert.strictEqual(result.total, 0);
  assert.deepStrictEqual(result.issues, []);
});

test('flags a cookie missing Secure/HttpOnly/SameSite', () => {
  const result = checkCookies(['session=abc123']);
  assert.strictEqual(result.total, 1);
  assert.strictEqual(result.issues.length, 3);
});

test('does not flag a fully-configured cookie', () => {
  const result = checkCookies(['session=abc123; Secure; HttpOnly; SameSite=Strict']);
  assert.strictEqual(result.issues.length, 0);
});

test('never includes the cookie value in the parsed output', () => {
  const result = checkCookies(['session=super-secret-token-value; Secure']);
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes('super-secret-token-value'));
});
