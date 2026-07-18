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
  const domainAttr = parts.find((p) => p.toLowerCase().startsWith('domain='));
  const pathAttr = parts.find((p) => p.toLowerCase().startsWith('path='));

  return {
    name,
    secure: attributes.includes('secure'),
    httpOnly: attributes.includes('httponly'),
    sameSite: attributes.includes('samesite')
      ? parts.find((p) => p.toLowerCase().startsWith('samesite')).split('=')[1] || '(no value)'
      : null,
    hasDomain: !!domainAttr,
    path: pathAttr ? pathAttr.split('=')[1] : '/',
  };
}

/**
 * Cookies named with a __Host- or __Secure- prefix are a browser-enforced
 * promise: if the prefix is used but the required attributes aren't
 * actually set, browsers silently refuse to set the cookie at all -
 * which usually manifests as a confusing login/session bug, not a
 * security hole, but is worth flagging since it means the prefix is
 * being used without understanding its requirements.
 */
function checkCookiePrefix(cookie) {
  if (cookie.name.startsWith('__Host-')) {
    const problems = [];
    if (!cookie.secure) problems.push('missing Secure');
    if (cookie.hasDomain) problems.push('has a Domain attribute (not allowed for __Host-)');
    if (cookie.path !== '/') problems.push('Path is not "/" (required for __Host-)');
    return problems.length ? problems : null;
  }
  if (cookie.name.startsWith('__Secure-')) {
    return !cookie.secure ? ['missing Secure'] : null;
  }
  return null;
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
    const prefixProblems = checkCookiePrefix(c);
    if (prefixProblems) {
      issues.push({
        cookie: c.name,
        severity: 'medium',
        note: `Cookie "${c.name}" uses a security-prefixed name but doesn't meet the prefix's requirements: ${prefixProblems.join(', ')}. Browsers will silently reject this cookie.`,
      });
    }
  });

  return {
    cookies: cookies.map((c) => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
    total: cookies.length,
    issues,
  };
}

module.exports = { checkCookies };
