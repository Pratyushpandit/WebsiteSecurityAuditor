/**
 * headerCheck.js
 * -----------------------------------------------------------------------
 * Passive analysis of HTTP response security headers. Read-only: this
 * only inspects headers already present on a normal GET response, it
 * never sends anything other than a single ordinary request.
 *
 * Each check includes a plain-English "explanation" of what the header
 * does and why an attacker cares, not just pass/fail, since a bare
 * PASS/FAIL is meaningless to anyone who doesn't already know what HSTS
 * or CSP are.
 */

const CHECKS = [
  {
    key: 'strict-transport-security',
    name: 'HTTP Strict Transport Security (HSTS)',
    severity: 'high',
    explanation:
      'Tells browsers to always connect over HTTPS, never plain HTTP, for this site. Without it, the first visit ' +
      '(or any visit after a cache clear) can be silently downgraded to HTTP by an attacker on the same network ' +
      '(e.g. public WiFi), letting them read or modify traffic before the browser ever reaches the real site.',
    remediation:
      'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to force browsers to always use HTTPS for this site.',
    evaluate: (value) => {
      if (!value) return { pass: false, note: 'Header is missing.' };
      const maxAgeMatch = value.match(/max-age=(\d+)/);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15552000) {
        return { pass: false, note: `max-age is only ${maxAge}s - recommend at least 15552000s (180 days).` };
      }
      return { pass: true, note: `max-age=${maxAge}s${value.includes('includeSubDomains') ? ', includeSubDomains' : ''}.` };
    },
  },
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy (CSP)',
    severity: 'high',
    explanation:
      'Whitelists which sources of scripts, styles, images, and other resources the browser is allowed to load and ' +
      'execute. It is the single most effective defense against cross-site scripting (XSS): even if an attacker ' +
      'manages to inject a <script> tag into the page, a good CSP stops the browser from running it.',
    remediation:
      'Add a Content-Security-Policy header to restrict which scripts, styles, and resources the browser will load, reducing XSS impact.',
    evaluate: (value) => {
      if (!value) return { pass: false, note: 'Header is missing.' };
      const flags = [];
      if (/script-src[^;]*'unsafe-inline'/.test(value)) flags.push("script-src allows 'unsafe-inline'");
      if (/script-src[^;]*'unsafe-eval'/.test(value)) flags.push("script-src allows 'unsafe-eval'");
      if (flags.length) return { pass: false, note: `Present but weakened: ${flags.join('; ')}.` };
      return { pass: true, note: 'Present with no unsafe-inline/unsafe-eval on script-src.' };
    },
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: 'medium',
    explanation:
      'Stops the browser from "MIME-sniffing" a response into a different content type than the server declared. ' +
      'Without it, a file the server serves as plain text or an image could be reinterpreted and executed as ' +
      'JavaScript or HTML by the browser in some scenarios, which is a route to XSS.',
    remediation: 'Add "X-Content-Type-Options: nosniff" to stop browsers from MIME-sniffing responses away from the declared type.',
    evaluate: (value) => (value && value.toLowerCase() === 'nosniff'
      ? { pass: true, note: 'Set to nosniff.' }
      : { pass: false, note: value ? `Unexpected value: ${value}` : 'Header is missing.' }),
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'medium',
    explanation:
      'Controls whether this page can be loaded inside an <iframe> on another site. Without it, an attacker can ' +
      'embed your login page (or any page) invisibly on their own site and trick users into clicking buttons they ' +
      "can't see — a technique called clickjacking.",
    remediation: 'Add "X-Frame-Options: DENY" or "SAMEORIGIN" (or a CSP frame-ancestors directive) to prevent clickjacking via iframes.',
    evaluate: (value) => {
      if (!value) return { pass: false, note: 'Header is missing.' };
      const v = value.toUpperCase();
      if (v === 'DENY' || v === 'SAMEORIGIN') return { pass: true, note: `Set to ${v}.` };
      return { pass: false, note: `Unexpected value: ${value}` };
    },
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'low',
    explanation:
      "Controls how much of this page's URL gets sent to other sites when a user clicks a link away from it. " +
      'Without a strict policy, full URLs — which can contain session tokens, search queries, or internal IDs in ' +
      'the query string — leak to every external site your pages link to, via the Referer header.',
    remediation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" (or stricter) to limit how much URL data leaks to other sites via the Referer header.',
    evaluate: (value) => (value
      ? { pass: true, note: `Set to "${value}".` }
      : { pass: false, note: 'Header is missing.' }),
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    severity: 'low',
    explanation:
      "Explicitly turns off browser features (camera, microphone, geolocation, USB, etc.) that this page doesn't " +
      'use. Without it, an XSS bug elsewhere on the site — or a compromised third-party script — has access to ' +
      'every browser feature by default instead of none.',
    remediation: 'Add a Permissions-Policy header to explicitly disable browser features (camera, microphone, geolocation, etc.) your site does not use.',
    evaluate: (value) => (value
      ? { pass: true, note: 'Present.' }
      : { pass: false, note: 'Header is missing.' }),
  },
];

function checkHeaders(headers) {
  const results = CHECKS.map((check) => {
    const rawValue = headers[check.key];
    const { pass, note } = check.evaluate(rawValue);
    return {
      id: check.key,
      name: check.name,
      severity: check.severity,
      explanation: check.explanation,
      pass,
      note,
      remediation: pass ? null : check.remediation,
      rawValue: rawValue || null,
    };
  });

  return {
    results,
    passCount: results.filter((r) => r.pass).length,
    total: results.length,
    versionDisclosure: checkVersionDisclosure(headers),
  };
}

/**
 * Server / X-Powered-By headers that reveal specific software versions
 * give an attacker a head start finding known CVEs for that exact
 * version. This only reports what the server is already broadcasting -
 * it doesn't look anything up or attempt to exploit anything.
 */
function checkVersionDisclosure(headers) {
  const findings = [];
  const versionPattern = /\/\d|\d+\.\d+/; // e.g. "Apache/2.4.41" or "PHP/8.1"

  ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'].forEach((key) => {
    const value = headers[key];
    if (value && versionPattern.test(value)) {
      findings.push({ header: key, value });
    }
  });

  return findings;
}

module.exports = { checkHeaders };
