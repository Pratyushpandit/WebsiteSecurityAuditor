const scopeList = document.getElementById('scope-list');
const scanButton = document.getElementById('scan-button');
const aboutToggle = document.getElementById('about-toggle');
const aboutBody = document.getElementById('about-body');

const emptyState = document.getElementById('empty-state');
const loadingState = document.getElementById('loading-state');
const loadingText = document.getElementById('loading-text');
const errorState = document.getElementById('error-state');
const reportCard = document.getElementById('report-card');

let selectedDomain = null;
let allowedDomains = [];

aboutToggle.addEventListener('click', () => {
  const hidden = aboutBody.hasAttribute('hidden');
  if (hidden) aboutBody.removeAttribute('hidden');
  else aboutBody.setAttribute('hidden', '');
  aboutToggle.textContent = hidden ? 'HOW SCOPE WORKS ▴' : 'HOW SCOPE WORKS ▾';
});

function setView(view) {
  emptyState.hidden = view !== 'empty';
  loadingState.hidden = view !== 'loading';
  errorState.hidden = view !== 'error';
  reportCard.hidden = view !== 'report';
}

async function loadAllowedDomains() {
  try {
    const res = await fetch('/api/allowed-domains');
    const data = await res.json();
    allowedDomains = data.domains || [];
  } catch (e) {
    allowedDomains = [];
  }
  renderScopeList();
}

function renderScopeList() {
  scopeList.innerHTML = '';

  if (allowedDomains.length === 0) {
    const li = document.createElement('li');
    li.className = 'scope-empty';
    li.textContent = 'No domains configured yet. Add hostnames to server/config/allowlist.js.';
    scopeList.appendChild(li);
    return;
  }

  allowedDomains.forEach((domain) => {
    const li = document.createElement('li');
    li.className = 'scope-item';
    li.dataset.domain = domain;
    li.innerHTML = `<span class="scope-dot"></span><span>${domain}</span>`;
    li.addEventListener('click', () => selectDomain(domain));
    scopeList.appendChild(li);
  });
}

function selectDomain(domain) {
  selectedDomain = domain;
  scanButton.disabled = false;
  document.querySelectorAll('.scope-item').forEach((el) => {
    el.classList.toggle('selected', el.dataset.domain === domain);
  });
}

scanButton.addEventListener('click', async () => {
  if (!selectedDomain) return;

  setView('loading');
  loadingText.textContent = `Scanning ${selectedDomain}…`;
  scanButton.disabled = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: `https://${selectedDomain}` }),
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Scan failed.');
    }

    renderReport(data);
    setView('report');
  } catch (err) {
    errorState.textContent = err.message;
    setView('error');
  } finally {
    scanButton.disabled = false;
  }
});

function renderReport(data) {
  document.getElementById('grade-badge').textContent = data.grade;
  document.getElementById('grade-badge').className = `grade-badge grade-${data.grade}`;
  document.getElementById('summary-url').textContent = data.hostname;
  document.getElementById('summary-meta').textContent =
    `Scanned ${new Date(data.scannedAt).toLocaleString()} · HTTP ${data.httpStatus} · Score ${data.score}/100 · ${data.durationMs}ms`;

  const countsEl = document.getElementById('severity-counts');
  countsEl.innerHTML = '';
  ['critical', 'high', 'medium', 'low'].forEach((sev) => {
    const count = data.counts[sev] || 0;
    if (count === 0) return;
    const pill = document.createElement('span');
    pill.className = `sev-pill ${sev}`;
    pill.textContent = `${count} ${sev}`;
    countsEl.appendChild(pill);
  });

  const findingsList = document.getElementById('findings-list');
  findingsList.innerHTML = '';
  if (data.findings.length === 0) {
    findingsList.innerHTML = '<div class="no-findings">No issues found across the checks performed. Nicely configured.</div>';
  } else {
    data.findings.forEach((f) => {
      const div = document.createElement('div');
      div.className = `finding ${f.severity}`;
      div.innerHTML = `
        <div class="finding-top">
          <span class="finding-title">${escapeHtml(f.title)}</span>
          <span class="finding-category">${escapeHtml(f.category)}</span>
        </div>
        <div class="finding-detail">${escapeHtml(f.detail)}</div>
        ${f.remediation ? `<div class="finding-remediation">${escapeHtml(f.remediation)}</div>` : ''}
      `;
      findingsList.appendChild(div);
    });
  }

  renderDetailGrid(data.details);
}

function renderDetailGrid(details) {
  const grid = document.getElementById('detail-grid');
  grid.innerHTML = '';

  // Headers card
  const headersCard = document.createElement('div');
  headersCard.className = 'detail-card';
  headersCard.innerHTML = `<h3>Security Headers (${details.headers.passCount}/${details.headers.total})</h3>` +
    details.headers.results.map((r) => `
      <div class="detail-row">
        <span class="k">${escapeHtml(r.name)}</span>
        <span class="v ${r.pass ? 'pass' : 'fail'}">${r.pass ? 'PASS' : 'FAIL'}</span>
      </div>
    `).join('');
  grid.appendChild(headersCard);

  // TLS card
  const tlsCard = document.createElement('div');
  tlsCard.className = 'detail-card';
  if (details.tls.error) {
    tlsCard.innerHTML = `<h3>TLS / Certificate</h3><div class="detail-row"><span class="k">${escapeHtml(details.tls.error)}</span></div>`;
  } else {
    const cert = details.tls.certificate;
    tlsCard.innerHTML = `<h3>TLS / Certificate</h3>` +
      `<div class="detail-row"><span class="k">Protocol</span><span class="v ${details.tls.isModernProtocol ? 'pass' : 'fail'}">${escapeHtml(details.tls.protocol || 'unknown')}</span></div>` +
      `<div class="detail-row"><span class="k">Cipher</span><span class="v">${escapeHtml(details.tls.cipher || 'unknown')}</span></div>` +
      `<div class="detail-row"><span class="k">Certificate trusted</span><span class="v ${details.tls.certificateTrusted ? 'pass' : 'fail'}">${details.tls.certificateTrusted ? 'YES' : 'NO'}</span></div>` +
      (cert ? `<div class="detail-row"><span class="k">Expires in</span><span class="v ${cert.daysRemaining > 14 ? 'pass' : 'fail'}">${cert.daysRemaining} days</span></div>` : '');
  }
  grid.appendChild(tlsCard);

  // Cookies card
  const cookiesCard = document.createElement('div');
  cookiesCard.className = 'detail-card';
  cookiesCard.innerHTML = `<h3>Cookies (${details.cookies.total})</h3>` +
    (details.cookies.total === 0
      ? '<div class="detail-row"><span class="k">No cookies set on this response</span></div>'
      : details.cookies.cookies.map((c) => `
          <div class="detail-row">
            <span class="k">${escapeHtml(c.name)}</span>
            <span class="v ${c.secure && c.httpOnly && c.sameSite ? 'pass' : 'fail'}">
              ${c.secure ? 'Secure ' : ''}${c.httpOnly ? 'HttpOnly ' : ''}${c.sameSite ? 'SameSite' : ''}
            </span>
          </div>
        `).join(''));
  grid.appendChild(cookiesCard);

  // Content card
  const contentCard = document.createElement('div');
  contentCard.className = 'detail-card';
  contentCard.innerHTML = `<h3>Content</h3>` +
    `<div class="detail-row"><span class="k">Mixed content resources</span><span class="v ${details.content.mixedContentCount === 0 ? 'pass' : 'fail'}">${details.content.mixedContentCount}</span></div>` +
    `<div class="detail-row"><span class="k">Forms found</span><span class="v">${details.content.forms.length}</span></div>` +
    `<div class="detail-row"><span class="k">POST forms without CSRF field</span><span class="v ${details.content.formsWithoutCsrfToken === 0 ? 'pass' : 'fail'}">${details.content.formsWithoutCsrfToken}</span></div>`;
  grid.appendChild(contentCard);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

loadAllowedDomains();
