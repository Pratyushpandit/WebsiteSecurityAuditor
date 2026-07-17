/**
 * headerCheck.js
 * -----------------------------------------------------------------------
 * Passive analysis of HTTP response security headers. Read-only: this
 * only inspects headers already present on a normal GET response, it
 * never sends anything other than a single ordinary request.
 */

const CHECKS = [
  {
    key: 'strict-transport-security',
    name: 'HTTP Strict Transport Security (HSTS)',
    severity: 'high',
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
    remediation: 'Add "X-Content-Type-Options: nosniff" to stop browsers from MIME-sniffing responses away from the declared type.',
    evaluate: (value) => (value && value.toLowerCase() === 'nosniff'
      ? { pass: true, note: 'Set to nosniff.' }
      : { pass: false, note: value ? `Unexpected value: ${value}` : 'Header is missing.' }),
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'medium',
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
    remediation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" (or stricter) to limit how much URL data leaks to other sites via the Referer header.',
    evaluate: (value) => (value
      ? { pass: true, note: `Set to "${value}".` }
      : { pass: false, note: 'Header is missing.' }),
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    severity: 'low',
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
  };
}

module.exports = { checkHeaders };
