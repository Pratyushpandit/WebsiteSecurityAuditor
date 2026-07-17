/**
 * scoring.js
 * -----------------------------------------------------------------------
 * Combines the header, TLS, cookie, and content check results into a
 * single letter grade (A-F) and a flat, severity-sorted findings list
 * for the dashboard. Deduction weights are deliberately simple and
 * documented here so the grade is easy to explain, not a black box.
 */

const SEVERITY_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function gradeFromScore(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

function buildFindings({ headers, tls, cookies, content }) {
  const findings = [];

  // Header findings
  headers.results
    .filter((r) => !r.pass)
    .forEach((r) => {
      findings.push({
        category: 'HTTP Headers',
        title: r.name,
        severity: r.severity,
        detail: r.note,
        remediation: r.remediation,
      });
    });

  // TLS findings
  if (tls.error) {
    findings.push({
      category: 'TLS / Certificate',
      title: 'TLS connection could not be established',
      severity: 'high',
      detail: tls.error,
      remediation: 'Verify the site serves valid HTTPS on port 443 and the certificate chain is complete.',
    });
  } else {
    if (!tls.certificateTrusted) {
      findings.push({
        category: 'TLS / Certificate',
        title: 'Certificate is not trusted',
        severity: 'critical',
        detail: tls.trustError || 'The certificate failed standard trust validation.',
        remediation: 'Install a certificate from a trusted CA (e.g. via Let\'s Encrypt) and ensure the full chain is served.',
      });
    }
    if (!tls.isModernProtocol) {
      findings.push({
        category: 'TLS / Certificate',
        title: `Outdated TLS protocol (${tls.protocol || 'unknown'})`,
        severity: 'high',
        detail: 'TLS 1.0/1.1 are deprecated and considered insecure.',
        remediation: 'Disable TLS 1.0/1.1 on the server and require TLS 1.2 or 1.3 only.',
      });
    }
    if (tls.certificate && tls.certificate.daysRemaining !== null) {
      if (tls.certificate.daysRemaining < 0) {
        findings.push({
          category: 'TLS / Certificate',
          title: 'Certificate has expired',
          severity: 'critical',
          detail: `Expired ${Math.abs(tls.certificate.daysRemaining)} day(s) ago.`,
          remediation: 'Renew the TLS certificate immediately.',
        });
      } else if (tls.certificate.daysRemaining < 14) {
        findings.push({
          category: 'TLS / Certificate',
          title: 'Certificate expiring soon',
          severity: 'medium',
          detail: `Expires in ${tls.certificate.daysRemaining} day(s).`,
          remediation: 'Renew the TLS certificate before it expires, ideally via automated renewal.',
        });
      }
    }
  }

  // Cookie findings
  cookies.issues.forEach((issue) => {
    findings.push({
      category: 'Cookies',
      title: `Cookie flag missing: ${issue.cookie}`,
      severity: issue.severity,
      detail: issue.note,
      remediation: 'Set Secure, HttpOnly, and SameSite on all cookies that don\'t explicitly need to be readable by client-side JS or sent cross-site.',
    });
  });

  // Content findings
  if (content.mixedContentCount > 0) {
    findings.push({
      category: 'Content',
      title: `${content.mixedContentCount} mixed-content resource(s) found`,
      severity: 'medium',
      detail: `HTTP resources loaded on an HTTPS page: ${content.mixedContent.slice(0, 5).map((m) => m.url).join(', ')}${content.mixedContentCount > 5 ? ', ...' : ''}`,
      remediation: 'Serve all page resources (scripts, images, stylesheets, iframes) over HTTPS.',
    });
  }
  if (content.formsWithoutCsrfToken > 0) {
    findings.push({
      category: 'Content',
      title: `${content.formsWithoutCsrfToken} POST form(s) with no visible CSRF token field`,
      severity: 'medium',
      detail: 'This is a static heuristic checking for a hidden field commonly used for CSRF tokens - it does not confirm server-side validation either way.',
      remediation: 'Ensure state-changing POST forms include and server-side-validate a CSRF token, or rely on SameSite cookies plus framework-level CSRF protection.',
    });
  }

  const severityRank = (s) => SEVERITY_ORDER.indexOf(s);
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  return findings;
}

function scoreScan(checkResults) {
  const findings = buildFindings(checkResults);
  const deduction = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  const score = Math.max(0, 100 - deduction);
  const grade = gradeFromScore(score);

  const counts = SEVERITY_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length;
    return acc;
  }, {});

  return { score, grade, findings, counts };
}

module.exports = { scoreScan, SEVERITY_WEIGHT, SEVERITY_ORDER };
