/**
 * corsCheck.js
 * -----------------------------------------------------------------------
 * Checks for a genuinely common and impactful misconfiguration: a server
 * that reflects an arbitrary Origin back in Access-Control-Allow-Origin
 * while also setting Access-Control-Allow-Credentials: true. That
 * combination lets ANY website read this site's authenticated API
 * responses (cookies included) on behalf of a logged-in visitor - one of
 * the few passively-detectable issues that regularly pays out on bug
 * bounty programs, because it's a real, confirmed impact rather than a
 * "best practice" gap.
 *
 * This sends a standard Origin header on an ordinary GET request - the
 * same header every browser sends automatically on cross-origin
 * requests. It does not attempt to steal any data or complete an actual
 * cross-origin read; it only inspects how the server responds.
 */

const axios = require('axios');

const PROBE_ORIGIN = 'https://cors-probe.invalid-example.test';

async function checkCors(targetUrl) {
  try {
    const response = await axios.get(targetUrl, {
      timeout: 8000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'WebsiteSecurityAuditor/1.0 (passive scan; +https://github.com/Pratyushpandit)',
        Origin: PROBE_ORIGIN,
      },
    });

    const acao = response.headers['access-control-allow-origin'];
    const acac = (response.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';

    if (!acao) {
      return { corsEnabled: false, reflectsArbitraryOrigin: false, allowsCredentials: false };
    }

    const reflectsArbitraryOrigin = acao === PROBE_ORIGIN;
    const wildcardWithCredentials = acao === '*' && acac;

    return {
      corsEnabled: true,
      allowOriginValue: acao,
      allowsCredentials: acac,
      reflectsArbitraryOrigin,
      wildcardWithCredentials,
      // The genuinely dangerous case: reflects any origin (or is a wildcard) AND allows credentials.
      isCritical: (reflectsArbitraryOrigin || wildcardWithCredentials) && acac,
    };
  } catch (err) {
    return { error: `CORS probe failed: ${err.message}` };
  }
}

module.exports = { checkCors };
