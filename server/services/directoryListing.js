/**
 * directoryListing.js
 * -----------------------------------------------------------------------
 * Checks a small list of common directory paths for an exposed
 * auto-generated "Index of /" listing (the default behavior of Apache
 * and Nginx when a directory has no index file and listing isn't
 * disabled). An open directory listing can reveal files that were never
 * meant to be linked from anywhere, and gives an attacker a map of the
 * site's file structure for free.
 *
 * Same category as exposureCheck.js: ordinary GET requests to
 * documented, common paths, nothing submitted, no authentication
 * bypassed.
 */

const axios = require('axios');

const COMMON_DIRS = ['/images/', '/uploads/', '/assets/', '/backup/', '/files/', '/data/', '/tmp/', '/old/'];

const LISTING_MARKERS = [/<title>Index of/i, /Index of \//i, /Parent Directory<\/a>/i];

function looksLikeDirectoryListing(body) {
  if (!body) return false;
  return LISTING_MARKERS.some((pattern) => pattern.test(body));
}

async function checkDirectoryListing(baseUrl) {
  const results = await Promise.all(
    COMMON_DIRS.map(async (dir) => {
      const url = new URL(dir, baseUrl).href;
      try {
        const response = await axios.get(url, {
          timeout: 6000,
          maxRedirects: 0,
          validateStatus: () => true,
          headers: { 'User-Agent': 'WebsiteSecurityAuditor/1.0 (passive scan; +https://github.com/Pratyushpandit)' },
        });
        const body = typeof response.data === 'string' ? response.data : '';
        const isListing = response.status === 200 && looksLikeDirectoryListing(body);
        return { path: dir, exposed: isListing, status: response.status };
      } catch {
        return { path: dir, exposed: false, status: null };
      }
    })
  );

  return {
    checked: results.length,
    exposed: results.filter((r) => r.exposed),
  };
}

module.exports = { checkDirectoryListing };
