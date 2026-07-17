const { test } = require('node:test');
const assert = require('node:assert');
const { checkContent } = require('../server/services/contentCheck');

test('detects mixed content on an https page', () => {
  const html = '<html><body><script src="http://insecure.example.com/a.js"></script></body></html>';
  const result = checkContent(html, 'https://example.com/');
  assert.strictEqual(result.mixedContentCount, 1);
  assert.strictEqual(result.mixedContent[0].type, 'script');
});

test('does not flag http resources on an http page as mixed content', () => {
  const html = '<html><body><script src="http://example.com/a.js"></script></body></html>';
  const result = checkContent(html, 'http://example.com/');
  assert.strictEqual(result.mixedContentCount, 0);
});

test('flags a POST form with no csrf-like field', () => {
  const html = '<form method="POST" action="/login"><input name="username"></form>';
  const result = checkContent(html, 'https://example.com/');
  assert.strictEqual(result.formsWithoutCsrfToken, 1);
});

test('does not flag a POST form that has a csrf-like field', () => {
  const html = '<form method="POST" action="/login"><input type="hidden" name="csrf_token" value="x"></form>';
  const result = checkContent(html, 'https://example.com/');
  assert.strictEqual(result.formsWithoutCsrfToken, 0);
});

test('does not flag GET forms for missing csrf field', () => {
  const html = '<form method="GET" action="/search"><input name="q"></form>';
  const result = checkContent(html, 'https://example.com/');
  assert.strictEqual(result.formsWithoutCsrfToken, 0);
});
