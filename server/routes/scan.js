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
const { checkCors } = require('../services/corsCheck');
const { checkDns } = require('../services/dnsCheck');
const { checkExposures } = require('../services/exposureCheck');
const { scoreScan } = require('../services/scoring');
const { generateReportPdf } = require('../services/pdfReport');

const router = express.Router();

// Lets the frontend render only the domains it's actually allowed to scan,
// instead of offering a free-text box that implies anything is fair game.
router.get('/allowed-domains', (req, res) => {
  res.json({ domains: ALLOWED_DOMAINS });
});

function validateAndAuthorize(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return { error: { status: 400, body: { error: 'Request body must include a "url" string.' } } };
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { error: { status: 400, body: { error: 'That is not a valid URL.' } } };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { error: { status: 400, body: { error: 'Only http:// and https:// URLs are supported.' } } };
  }

  // --- THE AUTHORIZATION GATE ---
  if (!isAuthorized(parsed.hostname)) {
    return {
      error: {
        status: 403,
        body: {
          error: `"${parsed.hostname}" is not on the authorized scan list.`,
          hint: 'This tool only scans domains the operator has explicitly allowlisted in server/config/allowlist.js. See /api/allowed-domains for the current list.',
        },
      },
    };
  }

  return { parsed };
}

async function runScan(parsed) {
  const scanStart = Date.now();
  const response = await fetchPage(parsed.href);
  const html = typeof response.data === 'string' ? response.data : '';

  const [tlsResults, corsResults, dnsResults, exposureResults] = await Promise.all([
    parsed.protocol === 'https:'
      ? checkTls(parsed.hostname)
      : Promise.resolve({ error: 'Site was loaded over plain HTTP - no TLS to inspect. Serving the site over HTTPS is itself a high-severity recommendation.' }),
    checkCors(parsed.href),
    checkDns(parsed.hostname),
    checkExposures(parsed.origin),
  ]);

  const headerResults = checkHeaders(response.headers || {});
  const cookieResults = checkCookies(response.headers['set-cookie']);
  const contentResults = checkContent(html, parsed.href);

  const { score, grade, findings, counts } = scoreScan({
    headers: headerResults,
    tls: tlsResults,
    cookies: cookieResults,
    content: contentResults,
    cors: corsResults,
    dns: dnsResults,
    exposures: exposureResults,
  });

  return {
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
      cors: corsResults,
      dns: dnsResults,
      exposures: exposureResults,
    },
  };
}

router.post('/scan', async (req, res) => {
  const { parsed, error } = validateAndAuthorize(req.body && req.body.url);
  if (error) return res.status(error.status).json(error.body);

  try {
    const result = await runScan(parsed);
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: `Scan failed: ${err.message}` });
  }
});

// Re-runs the scan and streams back a PDF instead of JSON. Re-scanning
// rather than caching keeps this endpoint simple and always current;
// scans are already fast enough (a handful of seconds) not to need caching.
router.post('/scan/report.pdf', async (req, res) => {
  const { parsed, error } = validateAndAuthorize(req.body && req.body.url);
  if (error) return res.status(error.status).json(error.body);

  try {
    const result = await runScan(parsed);
    const pdfBuffer = await generateReportPdf(result);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="security-report-${result.hostname}.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    res.status(502).json({ error: `Report generation failed: ${err.message}` });
  }
});

module.exports = router;
