/**
 * contentCheck.js
 * -----------------------------------------------------------------------
 * Passive HTML analysis. This only reads the page's own markup that was
 * already returned in the response - it never submits forms, never
 * sends alternate/malicious parameters, and never follows links to
 * other pages. Two things are checked:
 *
 *   1. Mixed content - HTTP resources (scripts, images, stylesheets,
 *      iframes) loaded on an HTTPS page, which browsers flag as
 *      insecure.
 *   2. CSRF token presence - a static heuristic that looks for a hidden
 *      input whose name suggests a CSRF/XSRF token on each <form>. This
 *      reports presence/absence only; it does not attempt to forge,
 *      guess, or bypass any token.
 */

const cheerio = require('cheerio');

function checkContent(html, pageUrl) {
  const $ = cheerio.load(html);
  const isHttps = pageUrl.startsWith('https://');

  const mixedContentSelectors = [
    ['script[src^="http://"]', 'script'],
    ['img[src^="http://"]', 'image'],
    ['link[rel="stylesheet"][href^="http://"]', 'stylesheet'],
    ['iframe[src^="http://"]', 'iframe'],
  ];

  const mixedContent = [];
  if (isHttps) {
    mixedContentSelectors.forEach(([selector, type]) => {
      $(selector).each((_, el) => {
        const src = $(el).attr('src') || $(el).attr('href');
        mixedContent.push({ type, url: src });
      });
    });
  }

  const forms = $('form');
  const formResults = [];
  forms.each((_, el) => {
    const form = $(el);
    const hasCsrfField =
      form.find('input[name*="csrf" i], input[name*="xsrf" i], input[name*="_token" i]').length > 0;
    formResults.push({
      action: form.attr('action') || '(current page)',
      method: (form.attr('method') || 'GET').toUpperCase(),
      hasPasswordField: form.find('input[type="password"]').length > 0,
      hasCsrfField,
    });
  });

  // Subresource Integrity: cross-origin scripts without an `integrity`
  // attribute will execute unmodified if that third-party host (a CDN,
  // typically) is ever compromised - the browser has no way to verify
  // the file it downloaded is the one the page author intended.
  let pageOrigin = null;
  try { pageOrigin = new URL(pageUrl).origin; } catch { /* leave null */ }

  const missingIntegrity = [];
  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (!src) return;
    let scriptOrigin = null;
    try { scriptOrigin = new URL(src, pageUrl).origin; } catch { return; }
    const isCrossOrigin = pageOrigin && scriptOrigin !== pageOrigin;
    const hasIntegrity = !!$(el).attr('integrity');
    if (isCrossOrigin && !hasIntegrity) {
      missingIntegrity.push(src);
    }
  });

  return {
    isHttps,
    mixedContent,
    mixedContentCount: mixedContent.length,
    forms: formResults,
    formsWithoutCsrfToken: formResults.filter((f) => f.method === 'POST' && !f.hasCsrfField).length,
    missingIntegrity,
    missingIntegrityCount: missingIntegrity.length,
  };
}

module.exports = { checkContent };
