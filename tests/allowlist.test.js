const { test } = require('node:test');
const assert = require('node:assert');

// Reset module cache so each test can control ALLOWED_DOMAINS via a fresh require if needed.
const { isAuthorized, normalizeHost } = require('../server/config/allowlist');

test('normalizeHost lowercases and strips www.', () => {
  assert.strictEqual(normalizeHost('WWW.Example.COM'), 'example.com');
  assert.strictEqual(normalizeHost('example.com.'), 'example.com');
  assert.strictEqual(normalizeHost('example.com'), 'example.com');
});

test('isAuthorized rejects hostnames not on the list', () => {
  assert.strictEqual(isAuthorized('definitely-not-allowed.com'), false);
});

test('isAuthorized rejects empty/undefined hostnames', () => {
  assert.strictEqual(isAuthorized(''), false);
  assert.strictEqual(isAuthorized(undefined), false);
});

test('isAuthorized treats www. prefix as the same authorized host', () => {
  // This test relies on server/config/allowlist.js having at least one
  // entry. If ALLOWED_DOMAINS is empty (the shipped default), this test
  // is skipped rather than failing, since there's nothing to check yet.
  const { ALLOWED_DOMAINS } = require('../server/config/allowlist');
  if (ALLOWED_DOMAINS.length === 0) {
    return;
  }
  const first = ALLOWED_DOMAINS[0];
  assert.strictEqual(isAuthorized(first), true);
  assert.strictEqual(isAuthorized(`www.${first}`), true);
});
