/**
 * scoring.js
 * -----------------------------------------------------------------------
 * Combines every check module's results into a single letter grade
 * (A-F) and a flat, severity-sorted findings list for the dashboard and
 * PDF report. Deduction weights are deliberately simple and documented
 * here so the grade is easy to explain, not a black box.
 *
 * Severity follows the same four working tiers used by CVSS and by
 * every major bug bounty program (Critical / High / Medium / Low), plus
 * Info for non-issues worth noting. There is no "extremely critical"
 * tier - Critical is already the ceiling, by design, so it stays
 * meaningful.
 */

const SEVERITY_WEIGHT = { critical: 30, high: 15, medium: 8, low: 3, info: 0 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function gradeFromScore(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

function buildFindings({ headers, tls, cookies, content, cors, dns, exposures }) {
  const findings = [];

  // ---- HTTP Headers ----
  headers.results
    .filter((r) => !r.pass)
    .forEach((r) => {
      findings.push({
        category: 'HTTP Headers',
        title: r.name,
        severity: r.severity,
        detail: r.note,
        explanation: r.explanation,
        remediation: r.remediation,
      });
    });

  (headers.versionDisclosure || []).forEach((v) => {
    findings.push({
      category: 'Information Disclosure',
      title: `Server software version disclosed (${v.header})`,
      severity: 'low',
      detail: `${v.header}: ${v.value}`,
      explanation: 'Broadcasting the exact software version gives an attacker a head start searching for known CVEs affecting that specific version, instead of having to fingerprint it first.',
      remediation: `Remove or genericize the "${v.header}" header at the server/proxy level so it doesn't reveal a specific version number.`,
    });
  });

  // ---- TLS / Certificate ----
  if (tls.error) {
    findings.push({
      category: 'TLS / Certificate',
      title: 'TLS connection could not be established',
      severity: 'high',
      detail: tls.error,
      explanation: 'Without valid HTTPS, all traffic to this site (including any login credentials) travels in a form that can be read or modified by anyone between the user and the server.',
      remediation: 'Verify the site serves valid HTTPS on port 443 and the certificate chain is complete.',
    });
  } else {
    if (!tls.certificateTrusted) {
      findings.push({
        category: 'TLS / Certificate',
        title: 'Certificate is not trusted',
        severity: 'critical',
        detail: tls.trustError || 'The certificate failed standard trust validation.',
        explanation: 'Browsers will show visitors a full-page security warning. Beyond scaring away legitimate users, it also trains them to click through TLS warnings, which is exactly the behavior that makes real man-in-the-middle attacks succeed.',
        remediation: "Install a certificate from a trusted CA (e.g. via Let's Encrypt) and ensure the full chain is served.",
      });
    }
    if (!tls.isModernProtocol) {
      findings.push({
        category: 'TLS / Certificate',
        title: `Outdated TLS protocol (${tls.protocol || 'unknown'})`,
        severity: 'high',
        detail: 'TLS 1.0/1.1 are deprecated and considered insecure.',
        explanation: 'TLS 1.0/1.1 have known cryptographic weaknesses and are disallowed by PCI-DSS. Most browsers show warnings or block these versions outright.',
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
          explanation: 'An expired certificate breaks HTTPS entirely for visitors - every browser shows a hard security interstitial, and most users will not click through it.',
          remediation: 'Renew the TLS certificate immediately.',
        });
      } else if (tls.certificate.daysRemaining < 14) {
        findings.push({
          category: 'TLS / Certificate',
          title: 'Certificate expiring soon',
          severity: 'medium',
          detail: `Expires in ${tls.certificate.daysRemaining} day(s).`,
          explanation: 'Once this certificate expires, the site will be entirely unreachable (or show security warnings) until it is renewed.',
          remediation: 'Renew the TLS certificate before it expires, ideally via automated renewal.',
        });
      }
    }
  }

  // ---- Cookies ----
  cookies.issues.forEach((issue) => {
    findings.push({
      category: 'Cookies',
      title: `Cookie issue: ${issue.cookie}`,
      severity: issue.severity,
      detail: issue.note,
      explanation: "Cookie flags control who can read a cookie (HttpOnly blocks JavaScript access), when it's sent (SameSite limits cross-site requests), and over what transport (Secure requires HTTPS). Missing flags widen the ways a session cookie can be stolen or misused.",
      remediation: "Set Secure, HttpOnly, and SameSite on all cookies that don't explicitly need to be readable by client-side JS or sent cross-site.",
    });
  });

  // ---- Content: mixed content, CSRF, SRI ----
  if (content.mixedContentCount > 0) {
    findings.push({
      category: 'Content',
      title: `${content.mixedContentCount} mixed-content resource(s) found`,
      severity: 'medium',
      detail: `HTTP resources loaded on an HTTPS page: ${content.mixedContent.slice(0, 5).map((m) => m.url).join(', ')}${content.mixedContentCount > 5 ? ', ...' : ''}`,
      explanation: 'Any resource loaded over plain HTTP on an otherwise-secure page can be intercepted and modified in transit, undermining the HTTPS protection on the rest of the page.',
      remediation: 'Serve all page resources (scripts, images, stylesheets, iframes) over HTTPS.',
    });
  }
  if (content.formsWithoutCsrfToken > 0) {
    findings.push({
      category: 'Content',
      title: `${content.formsWithoutCsrfToken} POST form(s) with no visible CSRF token field`,
      severity: 'medium',
      detail: 'This is a static heuristic checking for a hidden field commonly used for CSRF tokens - it does not confirm server-side validation either way.',
      explanation: "Without CSRF protection, a malicious site can trick a logged-in user's browser into submitting this form on their behalf, performing actions the user never intended.",
      remediation: 'Ensure state-changing POST forms include and server-side-validate a CSRF token, or rely on SameSite cookies plus framework-level CSRF protection.',
    });
  }
  if (content.missingIntegrityCount > 0) {
    findings.push({
      category: 'Content',
      title: `${content.missingIntegrityCount} cross-origin script(s) missing Subresource Integrity`,
      severity: 'low',
      detail: `Scripts loaded without an integrity attribute: ${content.missingIntegrity.slice(0, 5).join(', ')}${content.missingIntegrityCount > 5 ? ', ...' : ''}`,
      explanation: "If a third-party host (CDN, analytics provider, etc.) serving one of these scripts is ever compromised, the browser has no way to detect the file changed and will run whatever it's given.",
      remediation: 'Add an integrity="sha384-..." attribute (and crossorigin="anonymous") to cross-origin <script> tags, generated from the current file contents.',
    });
  }

  // ---- CORS ----
  if (cors && !cors.error) {
    if (cors.isCritical) {
      findings.push({
        category: 'CORS',
        title: 'CORS reflects arbitrary origin with credentials allowed',
        severity: 'critical',
        detail: `Access-Control-Allow-Origin: ${cors.allowOriginValue}, Access-Control-Allow-Credentials: true`,
        explanation: "This combination lets ANY website make authenticated, credentialed requests to this site's API on behalf of a logged-in visitor and read the response, effectively bypassing same-origin protection entirely. This is one of the few passively detectable CORS issues with confirmed, immediate impact.",
        remediation: 'Return a fixed allowlist of trusted origins from Access-Control-Allow-Origin instead of reflecting the request\'s Origin header, or disable Access-Control-Allow-Credentials if broad access is intended.',
      });
    } else if (cors.wildcardWithCredentials) {
      findings.push({
        category: 'CORS',
        title: 'CORS wildcard combined with credentials',
        severity: 'critical',
        detail: 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
        explanation: 'Modern browsers actually reject this specific combination, but it signals a fundamental misunderstanding of the CORS config that is worth fixing before it causes a real hole elsewhere.',
        remediation: 'Return a fixed allowlist of trusted origins instead of a wildcard when credentials are involved.',
      });
    }
  }

  // ---- DNS / Email security ----
  if (dns) {
    if (!dns.spf.present) {
      findings.push({
        category: 'DNS / Email Security',
        title: 'No SPF record found',
        severity: 'medium',
        detail: 'No TXT record starting with "v=spf1" was found for this domain.',
        explanation: 'Without SPF, mail servers have no authoritative list of which servers are allowed to send email as this domain, making it easier for attackers to spoof phishing emails that appear to come from this domain.',
        remediation: 'Publish an SPF TXT record listing your legitimate outgoing mail servers, e.g. "v=spf1 include:_spf.yourprovider.com ~all".',
      });
    }
    if (!dns.dmarc.present) {
      findings.push({
        category: 'DNS / Email Security',
        title: 'No DMARC record found',
        severity: 'medium',
        detail: 'No TXT record was found at _dmarc.<domain>.',
        explanation: 'DMARC tells receiving mail servers what to do with email that fails SPF/DKIM checks (quarantine, reject, or nothing). Without it, spoofed email impersonating this domain is more likely to reach inboxes.',
        remediation: 'Publish a DMARC TXT record, e.g. "v=DMARC1; p=quarantine; rua=mailto:you@yourdomain.com", then move to p=reject once you\'ve confirmed legitimate mail isn\'t affected.',
      });
    } else if (!dns.dmarc.isEnforcing) {
      findings.push({
        category: 'DNS / Email Security',
        title: `DMARC policy is not enforcing (p=${dns.dmarc.policy})`,
        severity: 'low',
        detail: dns.dmarc.record,
        explanation: 'A DMARC policy of "none" only requests reports - it doesn\'t actually stop spoofed email from being delivered.',
        remediation: "Move the DMARC policy to p=quarantine or p=reject once you've verified legitimate mail flows aren't affected.",
      });
    }
    if (!dns.caa.present) {
      findings.push({
        category: 'DNS / Email Security',
        title: 'No CAA record found',
        severity: 'low',
        detail: 'No Certificate Authority Authorization record was found for this domain.',
        explanation: 'CAA records restrict which certificate authorities are allowed to issue TLS certificates for this domain. Without one, any public CA can issue a certificate for it, widening the pool of CAs an attacker could target or exploit via misissuance.',
        remediation: 'Publish a CAA record restricting issuance to your actual certificate authority, e.g. \'0 issue "letsencrypt.org"\'.',
      });
    }
  }

  // ---- Exposed files / directories ----
  if (exposures) {
    exposures.exposed.forEach((e) => {
      findings.push({
        category: 'Exposed Files',
        title: e.label,
        severity: e.severity,
        detail: `Publicly accessible at ${e.path} (HTTP ${e.status})`,
        explanation: 'This file is sitting on the public web server, readable by anyone who requests it directly - no authentication bypass or exploitation involved, it was simply never restricted.',
        remediation: `Remove or block public access to ${e.path} at the web server/proxy level, and rotate any credentials it may have exposed.`,
      });
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
