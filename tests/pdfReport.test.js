const { test } = require('node:test');
const assert = require('node:assert');
const { generateReportPdf } = require('../server/services/pdfReport');

function mockScanResult(overrides = {}) {
  return {
    url: 'https://example.com/',
    scannedAt: new Date().toISOString(),
    httpStatus: 200,
    durationMs: 500,
    score: 90,
    grade: 'A',
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings: [],
    ...overrides,
  };
}

test('generates a valid PDF buffer for a clean scan', async () => {
  const buffer = await generateReportPdf(mockScanResult());
  assert.ok(Buffer.isBuffer(buffer));
  assert.ok(buffer.length > 100);
  assert.strictEqual(buffer.subarray(0, 5).toString(), '%PDF-');
});

test('generates a valid PDF for a scan with several findings', async () => {
  const result = mockScanResult({
    score: 55,
    grade: 'D',
    counts: { critical: 1, high: 1, medium: 2, low: 1, info: 0 },
    findings: [
      { category: 'Exposed Files', title: 'Exposed .env file', severity: 'critical', detail: 'Publicly accessible at /.env', explanation: 'Anyone can read it.', remediation: 'Remove it.' },
      { category: 'TLS / Certificate', title: 'Outdated TLS protocol', severity: 'high', detail: 'TLS 1.0 in use.', explanation: 'Weak crypto.', remediation: 'Disable TLS 1.0.' },
      { category: 'Cookies', title: 'Cookie issue: session', severity: 'medium', detail: 'Missing HttpOnly.', explanation: 'JS can read it.', remediation: 'Add HttpOnly.' },
      { category: 'DNS / Email Security', title: 'No SPF record found', severity: 'medium', detail: 'No SPF TXT record.', explanation: 'Spoofing risk.', remediation: 'Publish SPF.' },
      { category: 'Content', title: 'Missing SRI', severity: 'low', detail: '2 scripts.', explanation: 'Tampering risk.', remediation: 'Add integrity attr.' },
    ],
  });
  const buffer = await generateReportPdf(result);
  assert.ok(Buffer.isBuffer(buffer));
  assert.strictEqual(buffer.subarray(0, 5).toString(), '%PDF-');
});

test('does not throw on a finding with no explanation or remediation', async () => {
  const result = mockScanResult({
    findings: [{ category: 'Test', title: 'Bare finding', severity: 'low', detail: 'Just a detail.' }],
  });
  const buffer = await generateReportPdf(result);
  assert.ok(Buffer.isBuffer(buffer));
});
