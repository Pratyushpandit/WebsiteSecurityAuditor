/**
 * exposureCheck.js
 * -----------------------------------------------------------------------
 * Checks a small, fixed list of well-known paths that should never be
 * publicly accessible (source control metadata, environment files,
 * backups, framework debug endpoints). This is standard attack-surface
 * discovery - the same category of check every mainstream scanner
 * (Nuclei's "exposures" templates, Nikto, etc.) performs - not
 * exploitation: every request is an ordinary GET to a fixed, publicly
 * documented path, nothing is submitted, and no authentication is
 * bypassed. A hit here means the file was already sitting on the public
 * web server for anyone to request - the scan just checks and reports.
 */

const axios = require('axios');

const SENSITIVE_PATHS = [
  { path: '/.git/HEAD', label: 'Exposed .git repository', severity: 'critical' },
  { path: '/.git/config', label: 'Exposed .git configuration', severity: 'critical' },
  { path: '/.env', label: 'Exposed .env file (often contains credentials/API keys)', severity: 'critical' },
  { path: '/.env.local', label: 'Exposed .env.local file', severity: 'critical' },
  { path: '/wp-config.php.bak', label: 'Exposed WordPress config backup', severity: 'critical' },
  { path: '/config.php.bak', label: 'Exposed config backup file', severity: 'critical' },
  { path: '/backup.sql', label: 'Exposed SQL backup file', severity: 'critical' },
  { path: '/database.sql', label: 'Exposed SQL database dump', severity: 'critical' },
  { path: '/.DS_Store', label: 'Exposed .DS_Store (reveals directory listing)', severity: 'low' },
  { path: '/phpinfo.php', label: 'Exposed phpinfo() page (reveals server configuration)', severity: 'medium' },
  { path: '/.well-known/security.txt', label: 'security.txt present (informational, not a finding)', severity: 'info' },
  { path: '/server-status', label: 'Exposed Apache server-status page', severity: 'medium' },
];

// A handful of generic "not found" style responses return HTTP 200 with a
// friendly error page instead of a real 404. A short body full of common
// framework-config keywords is a stronger signal than status code alone.
function looksLikeRealHit(path, status, body) {
  if (status !== 200) return false;
  if (!body || body.length === 0) return false;
  if (body.length > 200000) return false; // huge body is very unlikely to be a leaked config/backup

  const lower = body.toLowerCase();
  if (lower.includes('<html') && (lower.includes('404') || lower.includes('not found') || lower.includes('page not found'))) {
    return false;
  }
  return true;
}

async function checkExposures(baseUrl) {
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async ({ path, label, severity }) => {
      const url = new URL(path, baseUrl).href;
      try {
        const response = await axios.get(url, {
          timeout: 6000,
          maxRedirects: 0, // a redirect (e.g. to a login page or homepage) means the path isn't really exposed
          validateStatus: () => true,
          headers: { 'User-Agent': 'WebsiteSecurityAuditor/1.0 (passive scan; +https://github.com/Pratyushpandit)' },
        });
        const body = typeof response.data === 'string' ? response.data : '';
        const exposed = looksLikeRealHit(path, response.status, body);
        return { path, label, severity, exposed, status: response.status };
      } catch {
        return { path, label, severity, exposed: false, status: null };
      }
    })
  );

  return {
    checked: results.length,
    exposed: results.filter((r) => r.exposed && r.severity !== 'info'),
    info: results.filter((r) => r.exposed && r.severity === 'info'),
  };
}

module.exports = { checkExposures, SENSITIVE_PATHS };
