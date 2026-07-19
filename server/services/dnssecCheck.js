/**
 * dnssecCheck.js
 * -----------------------------------------------------------------------
 * Checks whether a domain has DNSSEC configured, by querying for its
 * DNSKEY record. Node's built-in `dns` module doesn't support the
 * DNSKEY record type, so this uses DNS-over-HTTPS against Cloudflare's
 * public resolver (1.1.1.1) instead of adding a raw-DNS dependency -
 * still just an ordinary HTTPS GET to public DNS infrastructure, not a
 * request to the target itself.
 *
 * Without DNSSEC, a domain's DNS responses can't be cryptographically
 * verified, making cache-poisoning and DNS-spoofing attacks against its
 * visitors easier.
 */

const axios = require('axios');

async function checkDnssec(hostname) {
  try {
    const response = await axios.get('https://cloudflare-dns.com/dns-query', {
      params: { name: hostname, type: 'DNSKEY' },
      headers: { Accept: 'application/dns-json' },
      timeout: 6000,
    });

    const data = response.data;
    const hasDnskey = Array.isArray(data.Answer) && data.Answer.length > 0;
    // AD (Authenticated Data) flag means the resolver itself validated DNSSEC.
    const authenticatedData = !!data.AD;

    return { checked: true, enabled: hasDnskey, validated: authenticatedData };
  } catch (err) {
    return { checked: false, error: err.message };
  }
}

module.exports = { checkDnssec };
