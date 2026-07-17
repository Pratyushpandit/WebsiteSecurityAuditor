/**
 * cookieCheck.js
 * -----------------------------------------------------------------------
 * Passive inspection of Set-Cookie headers already present on the
 * response. This only checks for the presence/absence of the Secure,
 * HttpOnly, and SameSite attributes - it never reads, decodes, or
 * reports actual cookie values, since those can contain session tokens
 * or other sensitive data that has no business appearing in a report.
 */

function parseCookie(rawCookie) {
  const parts = rawCookie.split(';').map((p) => p.trim());
  const [nameValue] = parts;
  const [name] = nameValue.split('=');
  const attributes = parts.slice(1).map((p) => p.split('=')[0].toLowerCase());

  return {
    name,
    secure: attributes.includes('secure'),
    httpOnly: attributes.includes('httponly'),
    sameSite: attributes.includes('samesite')
      ? parts.find((p) => p.toLowerCase().startsWith('samesite')).split('=')[1] || '(no value)'
      : null,
  };
}

function checkCookies(setCookieHeader) {
  if (!setCookieHeader || setCookieHeader.length === 0) {
    return { cookies: [], total: 0, issues: [] };
  }

  const raw = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  const cookies = raw.map(parseCookie);

  const issues = [];
  cookies.forEach((c) => {
    if (!c.secure) {
      issues.push({ cookie: c.name, severity: 'medium', note: `Cookie "${c.name}" is missing the Secure attribute.` });
    }
    if (!c.httpOnly) {
      issues.push({ cookie: c.name, severity: 'medium', note: `Cookie "${c.name}" is missing the HttpOnly attribute (readable by JavaScript).` });
    }
    if (!c.sameSite) {
      issues.push({ cookie: c.name, severity: 'low', note: `Cookie "${c.name}" is missing the SameSite attribute (CSRF exposure).` });
    }
  });

  return {
    cookies: cookies.map((c) => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
    total: cookies.length,
    issues,
  };
}

module.exports = { checkCookies };
