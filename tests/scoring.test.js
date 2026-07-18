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

test('CORS reflecting arbitrary origin with credentials is a critical finding', () => {
  const { findings, grade } = scoreScan(
    baseline({ cors: { corsEnabled: true, allowOriginValue: 'https://evil.example', allowsCredentials: true, reflectsArbitraryOrigin: true, isCritical: true } })
  );
  const corsFinding = findings.find((f) => f.category === 'CORS');
  assert.ok(corsFinding);
  assert.strictEqual(corsFinding.severity, 'critical');
  assert.ok(['D', 'F', 'C'].includes(grade));
});

test('a well-configured CORS response produces no CORS finding', () => {
  const { findings } = scoreScan(
    baseline({ cors: { corsEnabled: true, allowOriginValue: 'https://trusted.example', allowsCredentials: false, reflectsArbitraryOrigin: false, isCritical: false } })
  );
  assert.strictEqual(findings.filter((f) => f.category === 'CORS').length, 0);
});

test('missing SPF/DMARC/CAA each produce a DNS finding', () => {
  const { findings } = scoreScan(
    baseline({ dns: { spf: { present: false }, dmarc: { present: false }, caa: { present: false } } })
  );
  const dnsFindings = findings.filter((f) => f.category === 'DNS / Email Security');
  assert.strictEqual(dnsFindings.length, 3);
});

test('present and enforcing DNS records produce no findings', () => {
  const { findings } = scoreScan(
    baseline({ dns: { spf: { present: true }, dmarc: { present: true, policy: 'reject', isEnforcing: true }, caa: { present: true } } })
  );
  assert.strictEqual(findings.filter((f) => f.category === 'DNS / Email Security').length, 0);
});

test('an exposed .env file is a critical finding', () => {
  const { findings, grade } = scoreScan(
    baseline({ exposures: { checked: 12, exposed: [{ path: '/.env', label: 'Exposed .env file', severity: 'critical', status: 200 }], info: [] } })
  );
  const exposureFinding = findings.find((f) => f.category === 'Exposed Files');
  assert.ok(exposureFinding);
  assert.strictEqual(exposureFinding.severity, 'critical');
  assert.notStrictEqual(grade, 'A');
});

test('no exposed files produces no Exposed Files findings', () => {
  const { findings } = scoreScan(baseline({ exposures: { checked: 12, exposed: [], info: [] } }));
  assert.strictEqual(findings.filter((f) => f.category === 'Exposed Files').length, 0);
});
