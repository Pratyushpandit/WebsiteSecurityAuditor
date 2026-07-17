/**
 * httpFetch.js
 * -----------------------------------------------------------------------
 * Performs exactly one ordinary GET request to the target URL - the same
 * request any browser makes to load the page. No alternate parameters,
 * no repeated requests with injected payloads, no probing of other
 * paths. This is the only network call the scanner makes to the target
 * besides the TLS handshake in tlsCheck.js.
 */

const axios = require('axios');

async function fetchPage(url) {
  const response = await axios.get(url, {
    timeout: 10000,
    maxRedirects: 5,
    validateStatus: () => true, // we want to inspect error responses too, not throw on them
    headers: {
      'User-Agent': 'WebsiteSecurityAuditor/1.0 (passive scan; +https://github.com/Pratyushpandit)',
    },
  });
  return response;
}

module.exports = { fetchPage };
