const { test } = require('node:test');
const assert = require('node:assert');
const { scoreScan } = require('../server/services/scoring');

function baseline(overrides = {}) {
  return {
    headers: { results: [], passCount: 0, total: 0 },
    tls: { protocol: 'TLSv1.3', cipher: 'X', certificateTrusted: true, isModernProtocol: true, certificate: { daysRemaining: 90 } },
    cookies: { cookies: [], total: 0, issues: [] },
    content: { mixedContentCount: 0, mixedContent: [], forms: [], formsWithoutCsrfToken: 0 },
    ...overrides,
  };
}

test('a clean scan scores 100 and grades A', () => {
  const { score, grade, findings } = scoreScan(baseline());
  assert.strictEqual(score, 100);
  assert.strictEqual(grade, 'A');
  assert.strictEqual(findings.length, 0);
});

test('an untrusted certificate is a critical finding and tanks the grade', () => {
  const { grade, findings } = scoreScan(
    baseline({ tls: { certificateTrusted: false, trustError: 'self signed', isModernProtocol: true, protocol: 'TLSv1.3', certificate: null } })
  );
  const critical = findings.find((f) => f.severity === 'critical');
  assert.ok(critical, 'expected a critical finding for untrusted certificate');
  assert.ok(['D', 'F'].includes(grade) || grade === 'C');
});

test('findings are sorted with highest severity first', () => {
  const { findings } = scoreScan(
    baseline({
      cookies: { cookies: [], total: 1, issues: [{ cookie: 'a', severity: 'low', note: 'x' }] },
      tls: { certificateTrusted: false, trustError: 'bad cert', isModernProtocol: true, protocol: 'TLSv1.3', certificate: null },
    })
  );
  assert.strictEqual(findings[0].severity, 'critical');
  assert.strictEqual(findings[findings.length - 1].severity, 'low');
});

test('missing HTTPS entirely (plain HTTP) surfaces as a high finding', () => {
  const { findings } = scoreScan(baseline({ tls: { error: 'Site was loaded over plain HTTP' } }));
  const httpFinding = findings.find((f) => f.category === 'TLS / Certificate');
  assert.ok(httpFinding);
  assert.strictEqual(httpFinding.severity, 'high');
});
