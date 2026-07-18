/**
 * dnsCheck.js
 * -----------------------------------------------------------------------
 * Passive DNS lookups for email-spoofing and certificate-issuance
 * protections: SPF, DMARC, and CAA records. These are ordinary DNS
 * queries - the same kind any mail server or certificate authority
 * performs automatically, not a scanning technique.
 */

const dns = require('dns/promises');

async function checkSpf(hostname) {
  try {
    const records = await dns.resolveTxt(hostname);
    const flat = records.map((r) => r.join(''));
    const spf = flat.find((r) => r.startsWith('v=spf1'));
    return spf ? { present: true, record: spf } : { present: false };
  } catch {
    return { present: false };
  }
}

async function checkDmarc(hostname) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${hostname}`);
    const flat = records.map((r) => r.join(''));
    const dmarc = flat.find((r) => r.startsWith('v=DMARC1'));
    if (!dmarc) return { present: false };

    const policyMatch = dmarc.match(/p=(\w+)/);
    const policy = policyMatch ? policyMatch[1] : 'none';
    return { present: true, record: dmarc, policy, isEnforcing: policy === 'reject' || policy === 'quarantine' };
  } catch {
    return { present: false };
  }
}

async function checkCaa(hostname) {
  try {
    const records = await dns.resolveCaa(hostname);
    return { present: records.length > 0, records };
  } catch {
    return { present: false, records: [] };
  }
}

async function checkDns(hostname) {
  const [spf, dmarc, caa] = await Promise.all([
    checkSpf(hostname),
    checkDmarc(hostname),
    checkCaa(hostname),
  ]);
  return { spf, dmarc, caa };
}

module.exports = { checkDns };
