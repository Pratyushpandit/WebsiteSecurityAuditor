/**
 * httpMethods.js
 * -----------------------------------------------------------------------
 * Sends a single OPTIONS request (a standard, read-only HTTP method
 * whose entire purpose is to ask the server what it supports) and
 * checks the returned Allow header for methods that are risky to leave
 * enabled on a general web server: PUT/DELETE (unauthenticated write
 * access if misconfigured) and TRACE (enables the Cross-Site Tracing
 * attack, which can leak cookies marked HttpOnly).
 *
 * This does not attempt to actually use any of these methods against
 * the target - it only reads what the OPTIONS response says is allowed.
 */

const axios = require('axios');

const RISKY_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];

async function checkHttpMethods(targetUrl) {
  try {
    const response = await axios.request({
      method: 'OPTIONS',
      url: targetUrl,
      timeout: 6000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'WebsiteSecurityAuditor/1.0 (passive scan; +https://github.com/Pratyushpandit)' },
    });

    const allowHeader = response.headers['allow'] || response.headers['access-control-allow-methods'] || '';
    if (!allowHeader) {
      return { checked: true, allowHeader: null, riskyMethodsAllowed: [] };
    }

    const methods = allowHeader.split(',').map((m) => m.trim().toUpperCase());
    const riskyMethodsAllowed = methods.filter((m) => RISKY_METHODS.includes(m));

    return { checked: true, allowHeader, riskyMethodsAllowed };
  } catch (err) {
    return { checked: false, error: err.message };
  }
}

module.exports = { checkHttpMethods };
