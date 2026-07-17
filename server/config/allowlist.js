/**
 * allowlist.js
 * -----------------------------------------------------------------------
 * THE AUTHORIZATION BOUNDARY.
 *
 * This is the only place that decides which hosts the auditor is allowed
 * to scan. Every scan request is checked against this list on the server
 * BEFORE any network request is made to the target - the UI has no way
 * to bypass it, because the check happens here, not in the browser.
 *
 * This tool intentionally has no "scan any URL" mode and no self-service
 * way to add a domain from the UI. Adding a site here means the
 * repository owner has redeployed the server with that domain included -
 * i.e. it requires the same level of access as deploying the site itself.
 *
 * To add a site you own:
 *   1. Add its exact hostname below (no protocol, no path, no port).
 *   2. Redeploy the server.
 *
 * Do NOT add a domain you do not own or have explicit written permission
 * to test. Scanning a domain you don't control is unauthorized access in
 * most jurisdictions, even for read-only/passive checks.
 */

const ALLOWED_DOMAINS = [
  // Examples - replace with your actual deployed domains before use.
  // 'yourproject.netlify.app',
  'esewa.com.np'
  // 'yourname.infinityfreeapp.com',
  // 'yourdomain.je',
];

/**
 * Normalize a hostname for comparison: lowercase, strip a trailing dot,
 * strip a leading "www." so "www.example.com" and "example.com" are
 * treated as the same authorized target.
 */
function normalizeHost(hostname) {
  return hostname
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^www\./, '');
}

function isAuthorized(hostname) {
  if (!hostname) return false;
  const normalized = normalizeHost(hostname);
  return ALLOWED_DOMAINS.some((allowed) => normalizeHost(allowed) === normalized);
}

module.exports = { ALLOWED_DOMAINS, isAuthorized, normalizeHost };
