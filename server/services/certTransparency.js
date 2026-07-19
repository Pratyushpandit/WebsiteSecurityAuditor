/**
 * certTransparency.js
 * -----------------------------------------------------------------------
 * Queries crt.sh, a public Certificate Transparency log search engine,
 * for every certificate ever issued for this domain. CT logs are public
 * by design (every publicly-trusted certificate must be logged) - this
 * queries a public log about the domain, not the target server itself,
 * the same way a search engine query would. It often surfaces forgotten
 * subdomains (staging., old-admin., dev-api.) that the current site
 * owner may not remember exist and that were never intended to stay
 * reachable.
 */

const axios = require('axios');

async function checkCertTransparency(hostname) {
  try {
    const response = await axios.get('https://crt.sh/', {
      params: { q: hostname, output: 'json' },
      timeout: 10000,
      headers: { 'User-Agent': 'WebsiteSecurityAuditor/1.0 (passive scan; +https://github.com/Pratyushpandit)' },
    });

    const entries = Array.isArray(response.data) ? response.data : [];
    const subdomains = new Set();

    entries.forEach((entry) => {
      (entry.name_value || '').split('\n').forEach((name) => {
        const clean = name.trim().toLowerCase();
        if (clean && clean.endsWith(hostname.toLowerCase()) && clean !== hostname.toLowerCase() && !clean.startsWith('*.')) {
          subdomains.add(clean);
        }
      });
    });

    return {
      checked: true,
      certificateCount: entries.length,
      discoveredSubdomains: Array.from(subdomains).sort(),
    };
  } catch (err) {
    // crt.sh is a third-party service and occasionally rate-limits or times
    // out - fail soft rather than breaking the whole scan over it.
    return { checked: false, error: err.message };
  }
}

module.exports = { checkCertTransparency };
