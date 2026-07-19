/**
 * subdomainTakeover.js
 * -----------------------------------------------------------------------
 * Checks whether this hostname's CNAME points at a third-party service
 * (GitHub Pages, Heroku, S3, Netlify, etc.) and, if so, whether that
 * service is currently returning an "unclaimed resource" fingerprint -
 * the signature of a subdomain takeover vulnerability, where an
 * attacker could register the abandoned resource and serve their own
 * content from this domain.
 *
 * This is passive recon: one DNS lookup (CNAME) plus reading the body of
 * the page the scan already fetches. It never registers, claims, or
 * attempts to take over anything - it only detects the *possibility* by
 * matching known "not found" text that these providers show for
 * unclaimed resources.
 *
 * Fingerprint list is a small, well-known subset of the patterns
 * documented publicly by the security community (e.g. the
 * "can-i-take-over-xyz" reference project).
 */

const dns = require('dns/promises');

const FINGERPRINTS = [
  { service: 'GitHub Pages', cnamePattern: /github\.io$/i, bodyPattern: /There isn't a GitHub Pages site here/i },
  { service: 'Heroku', cnamePattern: /herokuapp\.com$/i, bodyPattern: /No such app/i },
  { service: 'Amazon S3', cnamePattern: /s3.*\.amazonaws\.com$/i, bodyPattern: /NoSuchBucket/i },
  { service: 'Microsoft Azure', cnamePattern: /azurewebsites\.net$|cloudapp\.net$/i, bodyPattern: /404 Web Site not found/i },
  { service: 'Netlify', cnamePattern: /netlify\.app$/i, bodyPattern: /Not Found - Request ID/i },
  { service: 'Surge.sh', cnamePattern: /surge\.sh$/i, bodyPattern: /project not found/i },
  { service: 'Bitbucket', cnamePattern: /bitbucket\.io$/i, bodyPattern: /Repository not found/i },
  { service: 'Fastly', cnamePattern: /fastly\.net$/i, bodyPattern: /Fastly error: unknown domain/i },
  { service: 'Zendesk', cnamePattern: /zendesk\.com$/i, bodyPattern: /Help Center Closed/i },
  { service: 'Pantheon', cnamePattern: /pantheonsite\.io$/i, bodyPattern: /The gods are wise/i },
  { service: 'WordPress.com', cnamePattern: /wordpress\.com$/i, bodyPattern: /Do you want to register/i },
];

async function checkSubdomainTakeover(hostname, alreadyFetchedBody) {
  let cnameChain = [];
  try {
    cnameChain = await dns.resolveCname(hostname);
  } catch {
    return { hasCname: false, vulnerable: false };
  }

  if (!cnameChain.length) {
    return { hasCname: false, vulnerable: false };
  }

  const target = cnameChain[cnameChain.length - 1];
  const matchedService = FINGERPRINTS.find((fp) => fp.cnamePattern.test(target));

  if (!matchedService) {
    return { hasCname: true, cname: target, matchedService: null, vulnerable: false };
  }

  // Reuse the page body the main scan already fetched rather than making
  // another request, when available.
  const bodyToCheck = alreadyFetchedBody || '';
  const vulnerable = matchedService.bodyPattern.test(bodyToCheck);

  return {
    hasCname: true,
    cname: target,
    matchedService: matchedService.service,
    vulnerable,
  };
}

module.exports = { checkSubdomainTakeover };
