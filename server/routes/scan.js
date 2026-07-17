/**
 * scan.js
 * -----------------------------------------------------------------------
 * The only route that talks to a target site. Every request is checked
 * against the allowlist FIRST - if the hostname isn't authorized, the
 * function returns immediately and no network request is ever made to
 * the target. This ordering is deliberate and should not be changed:
 * authorization must be the first thing that happens, not a check that
 * happens to run before the response is sent.
 */

const express = require('express');
const { URL } = require('url');

const { isAuthorized, ALLOWED_DOMAINS, normalizeHost } = require('../config/allowlist');
const { fetchPage } = require('../services/httpFetch');
const { checkHeaders } = require('../services/headerCheck');
const { checkTls } = require('../services/tlsCheck');
const { checkCookies } = require('../services/cookieCheck');
const { checkContent } = require('../services/contentCheck');
const { scoreScan } = require('../services/scoring');

const router = express.Router();

// Lets the frontend render only the domains it's actually allowed to scan,
// instead of offering a free-text box that implies anything is fair game.
router.get('/allowed-domains', (req, res) => {
  res.json({ domains: ALLOWED_DOMAINS });
});

router.post('/scan', async (req, res) => {
  const { url: targetUrl } = req.body || {};

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'Request body must include a "url" string.' });
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: 'That is not a valid URL.' });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return res.status(400).json({ error: 'Only http:// and https:// URLs are supported.' });
  }

  // --- THE AUTHORIZATION GATE ---
  if (!isAuthorized(parsed.hostname)) {
    return res.status(403).json({
      error: `"${parsed.hostname}" is not on the authorized scan list.`,
      hint: 'This tool only scans domains the operator has explicitly allowlisted in server/config/allowlist.js. See /api/allowed-domains for the current list.',
    });
  }

  const scanStart = Date.now();
  try {
    const response = await fetchPage(parsed.href);
    const html = typeof response.data === 'string' ? response.data : '';

    const headerResults = checkHeaders(response.headers || {});
    const tlsResults = parsed.protocol === 'https:'
      ? await checkTls(parsed.hostname)
      : { error: 'Site was loaded over plain HTTP - no TLS to inspect. Serving the site over HTTPS is itself a high-severity recommendation.' };
    const cookieResults = checkCookies(response.headers['set-cookie']);
    const contentResults = checkContent(html, parsed.href);

    const { score, grade, findings, counts } = scoreScan({
      headers: headerResults,
      tls: tlsResults,
      cookies: cookieResults,
      content: contentResults,
    });

    res.json({
      url: parsed.href,
      hostname: normalizeHost(parsed.hostname),
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - scanStart,
      httpStatus: response.status,
      score,
      grade,
      counts,
      findings,
      details: {
        headers: headerResults,
        tls: tlsResults,
        cookies: cookieResults,
        content: contentResults,
      },
    });
  } catch (err) {
    res.status(502).json({ error: `Scan failed: ${err.message}` });
  }
});

module.exports = router;
