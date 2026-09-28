let currentResult = null;
let activeCategory = 'All';

function fmtTime(iso) {
  if (!iso) return 'not scanned yet';
  const d = new Date(iso);
  return `scanned ${d.toLocaleTimeString()}`;
}

function statusClass(f) {
  if (f.inferred) return 'inferred';
  return f.verified ? 'verified' : 'community';
}

function signalBars(confidence) {
  const steps = [25, 50, 75, 100];
  return steps.map(s => `<i class="${confidence >= s ? 'on' : ''}"></i>`).join('');
}

function buildCategoryList(findings) {
  const cats = new Set();
  findings.forEach(f => (f.categories || []).forEach(c => cats.add(c)));
  return ['All', ...[...cats].sort()];
}

function renderFilters(findings) {
  const wrap = document.getElementById('categoryFilters');
  const cats = buildCategoryList(findings);
  wrap.innerHTML = cats.map(c =>
    `<button class="chip ${c === activeCategory ? 'active' : ''}" data-cat="${escapeHtml(c)}">${escapeHtml(c)}</button>`
  ).join('');
  wrap.querySelectorAll('.chip').forEach(btn => {
    btn.addEventListener('click', () => {
      activeCategory = btn.dataset.cat;
      renderResults();
      renderFilters(findings);
    });
  });
}

function evidenceLine(e) {
  const parts = [`<b>${escapeHtml(e.signal)}</b>`];
  if (e.matched) parts.push(`→ "${escapeHtml(e.matched)}"`);
  parts.push(`(w:${e.confidence})`);
  return parts.join(' ');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderResults() {
  const container = document.getElementById('results');
  const empty = document.getElementById('emptyState');
  if (!currentResult || !currentResult.findings || currentResult.findings.length === 0) {
    container.innerHTML = '';
    container.appendChild(empty);
    return;
  }

  const findings = currentResult.findings.filter(f =>
    activeCategory === 'All' || (f.categories || []).includes(activeCategory)
  );

  container.innerHTML = findings.map((f, i) => {
    const vulnBadge = f.vulnerabilities?.length
      ? `<span class="vuln-flag">${f.vulnerabilities.length} CVE</span>` : '';
    const evidenceHtml = f.evidence.map(e => `<div class="evidence-item">${evidenceLine(e)}</div>`).join('');
    const vulnHtml = (f.vulnerabilities || []).map(v =>
      `<div class="vuln-item">${v.cve} (${v.severity}) — ${escapeHtml(v.summary)}</div>`
    ).join('');
    const liveCveBtn = f.version
      ? `<button class="link-btn live-cve-btn" data-name="${escapeHtml(f.name)}" data-version="${escapeHtml(f.version)}">check live CVEs (NVD) →</button>
         <div class="live-cve-results" id="liveCveResults-${i}"></div>`
      : '';
    const osvBtn = f.version
      ? `<button class="link-btn osv-btn" data-name="${escapeHtml(f.name)}" data-version="${escapeHtml(f.version)}">check OSV.dev →</button>
         <div class="osv-results" id="osvResults-${i}"></div>`
      : '';
    const cpeBtn = (f.version && TECH_TO_CPE[f.name])
      ? `<button class="link-btn cpe-btn" data-name="${escapeHtml(f.name)}" data-version="${escapeHtml(f.version)}" title="Experimental — precise CPE-based match instead of fuzzy keyword search. See lib/cpe-lookup.js for what's and isn't verified.">check precise CVE match (CPE, experimental) →</button>
         <div class="cpe-results" id="cpeResults-${i}"></div>`
      : '';
    const localCveIds = (f.vulnerabilities || []).map(v => v.cve);
    const confirmExploitBtn = localCveIds.length
      ? `<button class="link-btn confirm-exploit-btn" data-idx="${i}" data-cves="${escapeHtml(localCveIds.join(','))}">confirm exploitation status (CISA KEV + EPSS + GHSA) →</button>
         <div class="confirm-exploit-results" id="confirmExploitResults-${i}"></div>`
      : '';
    return `
      <div class="finding" data-idx="${i}">
        <div class="finding-row">
          <span class="status-dot ${statusClass(f)}"></span>
          <span class="finding-name">${escapeHtml(f.name)}</span>
          ${f.version ? `<span class="finding-version" title="${f.versionConflict ? 'Signals disagree on version — see details' : ''}">v${escapeHtml(f.version)}${f.versionConflict ? ' ⚠' : ''}</span>` : ''}
          ${vulnBadge}
          <span class="kev-flag" id="kevFlag-${i}"></span>
          ${f.custom ? '<span class="vuln-flag" style="color:var(--cyan);border-color:rgba(79,209,197,0.4)">custom</span>' : ''}
          <span class="finding-cat">${(f.categories || []).join(', ')}</span>
          <span class="signal-bars">${signalBars(f.confidence)}</span>
        </div>
        <div class="evidence-log">
          <div class="evidence-item"><b>confidence:</b> ${f.confidence}/100</div>
          ${f.versionConflict ? `<div class="evidence-item version-conflict-note">⚠ <b>signals disagree on version:</b> ${f.allVersionsFound.map(v => escapeHtml(v)).join(' vs. ')} — showing the highest-confidence one above, but the disagreement itself may be informative (stale cache, in-progress upgrade, etc.)</div>` : ''}
          ${evidenceHtml}
          ${vulnHtml}
          ${confirmExploitBtn}
          ${liveCveBtn}
          ${osvBtn}
          ${cpeBtn}
        </div>
      </div>`;
  }).join('');

  container.querySelectorAll('.finding').forEach(el => {
    el.addEventListener('click', () => el.classList.toggle('open'));
  });

  container.querySelectorAll('.confirm-exploit-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const cveIds = btn.dataset.cves.split(',').filter(Boolean);
      const idx = btn.dataset.idx;
      const resultsEl = btn.nextElementSibling;
      btn.textContent = 'checking CISA KEV + EPSS + GHSA…';
      btn.disabled = true;
      try {
        const [kevResp, epssResp, ghsaResp] = await Promise.all([
          chrome.runtime.sendMessage({ type: 'ISA_CHECK_KEV', cveIds }),
          chrome.runtime.sendMessage({ type: 'ISA_CHECK_EPSS', cveIds }),
          chrome.runtime.sendMessage({ type: 'ISA_CHECK_GHSA', cveIds })
        ]);
        renderExploitConfirmation(resultsEl, cveIds, kevResp, epssResp, ghsaResp);
        // Persist a visible flag on the collapsed finding row too, not just
        // in the expanded evidence log — a confirmed-exploited finding
        // shouldn't require expanding every row to notice during triage.
        const kevFlagEl = document.getElementById(`kevFlag-${idx}`);
        if (kevFlagEl && kevResp?.ok && kevResp.matches.length > 0) {
          kevFlagEl.innerHTML = `<span class="vuln-flag kev-inline-flag" title="Confirmed in CISA's Known Exploited Vulnerabilities catalog">⚠ actively exploited</span>`;
          for (const m of kevResp.matches) kevConfirmedThisSession.add(m.cve.toUpperCase());
          renderRiskScore();
        }
      } catch {
        resultsEl.innerHTML = `<div class="live-cve-error">Lookup failed — try again.</div>`;
      } finally {
        btn.textContent = 'confirm exploitation status (CISA KEV + EPSS + GHSA) →';
        btn.disabled = false;
      }
    });
  });

  container.querySelectorAll('.live-cve-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const { name, version } = btn.dataset;
      const idx = btn.closest('.finding').dataset.idx;
      const resultsEl = document.getElementById(`liveCveResults-${idx}`);
      btn.textContent = 'querying NVD…';
      btn.disabled = true;
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'ISA_CHECK_LIVE_CVE', techName: name, version });
        renderLiveCveResults(resultsEl, resp);
      } catch {
        resultsEl.innerHTML = `<div class="live-cve-error">Lookup failed — try again.</div>`;
      } finally {
        btn.textContent = 'check live CVEs (NVD) →';
        btn.disabled = false;
      }
    });
  });

  container.querySelectorAll('.osv-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const { name, version } = btn.dataset;
      const idx = btn.closest('.finding').dataset.idx;
      const resultsEl = document.getElementById(`osvResults-${idx}`);
      btn.textContent = 'querying OSV.dev…';
      btn.disabled = true;
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'ISA_CHECK_OSV', techName: name, version });
        renderOsvResults(resultsEl, resp);
      } catch {
        resultsEl.innerHTML = `<div class="live-cve-error">Lookup failed — try again.</div>`;
      } finally {
        btn.textContent = 'check OSV.dev →';
        btn.disabled = false;
      }
    });
  });

  container.querySelectorAll('.cpe-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const { name, version } = btn.dataset;
      const idx = btn.closest('.finding').dataset.idx;
      const resultsEl = document.getElementById(`cpeResults-${idx}`);
      btn.textContent = 'querying NVD (CPE)…';
      btn.disabled = true;
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'ISA_CHECK_CPE_MATCH', techName: name, version });
        renderCpeResults(resultsEl, resp);
      } catch {
        resultsEl.innerHTML = `<div class="live-cve-error">Lookup failed — try again.</div>`;
      } finally {
        btn.textContent = 'check precise CVE match (CPE, experimental) →';
        btn.disabled = false;
      }
    });
  });
}

function renderCpeResults(el, resp) {
  if (!resp || !resp.ok) {
    el.innerHTML = `<div class="live-cve-error">${escapeHtml(resp?.error || 'lookup failed')}</div>`;
    return;
  }
  if (!resp.results.length) {
    el.innerHTML = `<div class="live-cve-empty">No CVEs found via exact CPE match at this version.</div>`;
    return;
  }
  el.innerHTML = resp.results.map(r => `
    <div class="live-cve-item">
      <div class="live-cve-head">
        <span class="live-cve-id">${escapeHtml(r.id)}</span>
        ${r.severity ? `<span class="live-cve-sev sev-${escapeHtml(r.severity.toLowerCase())}">${escapeHtml(r.severity)}${r.score ? ` ${r.score}` : ''}</span>` : ''}
      </div>
      ${r.description ? `<div class="live-cve-desc">${escapeHtml(r.description)}</div>` : ''}
    </div>`).join('');
}

function renderOsvResults(el, resp) {
  if (!resp || !resp.ok) {
    el.innerHTML = `<div class="live-cve-error">${escapeHtml(resp?.error || 'lookup failed')}</div>`;
    return;
  }
  if (resp.skipped) {
    el.innerHTML = `<div class="live-cve-empty">ISA doesn't have a verified package-registry mapping for this technology yet — OSV lookup skipped rather than guessed.</div>`;
    return;
  }
  if (!resp.vulns.length) {
    el.innerHTML = `<div class="live-cve-empty">No vulnerabilities found on OSV.dev for ${escapeHtml(resp.package.ecosystem)}:${escapeHtml(resp.package.name)} at this version.</div>`;
    return;
  }
  el.innerHTML = resp.vulns.map(v => `
    <div class="live-cve-item">
      <div class="live-cve-head">
        <span class="live-cve-id">${escapeHtml(v.id)}</span>
        ${v.cveAliases.length ? `<span class="osv-cve-alias">${v.cveAliases.map(escapeHtml).join(', ')}</span>` : `<span class="osv-cve-alias osv-no-cve">no CVE assigned</span>`}
        ${v.severity ? `<span class="live-cve-sev">CVSS ${escapeHtml(v.severity)}</span>` : ''}
      </div>
      ${v.summary ? `<div class="live-cve-desc">${escapeHtml(v.summary)}</div>` : ''}
      ${v.references.length ? `<div class="live-cve-links">${v.references.map(u => `<a href="${escapeHtml(u)}" target="_blank" rel="noopener">reference</a>`).join(' ')}</div>` : ''}
    </div>`).join('');
}

function renderLiveCveResults(el, resp) {
  if (!resp || !resp.ok) {
    el.innerHTML = `<div class="live-cve-error">${escapeHtml(resp?.error || 'lookup failed')}</div>`;
    return;
  }
  const filterNote = resp.filteredCount
    ? `<div class="live-cve-filtered">${resp.filteredCount} NVD result${resp.filteredCount === 1 ? '' : 's'} omitted — description didn't actually mention this technology (likely unrelated keyword-search noise).</div>`
    : '';
  if (!resp.results.length) {
    el.innerHTML = `<div class="live-cve-empty">No CVEs found on NVD for this exact query${resp.cached ? ' (cached)' : ''}.</div>` + filterNote;
    return;
  }
  el.innerHTML = (resp.cached ? `<div class="live-cve-cached">from cache</div>` : '') + filterNote + resp.results.map(r => `
    <div class="live-cve-item">
      <div class="live-cve-head">
        <span class="live-cve-id">${escapeHtml(r.id)}</span>
        ${r.severity ? `<span class="live-cve-sev sev-${escapeHtml(r.severity.toLowerCase())}">${escapeHtml(r.severity)}${r.score ? ` ${r.score}` : ''}</span>` : ''}
      </div>
      <div class="live-cve-desc">${escapeHtml(r.description)}</div>
      <div class="live-cve-links">
        <a href="${escapeHtml(r.links.nvd)}" target="_blank" rel="noopener">NVD</a>
        <a href="${escapeHtml(r.links.exploitdb)}" target="_blank" rel="noopener">Exploit-DB</a>
        <a href="${escapeHtml(r.links.githubAdvisories)}" target="_blank" rel="noopener">GitHub Advisories</a>
        <a href="${escapeHtml(r.links.mitreHuman)}" target="_blank" rel="noopener">MITRE</a>
      </div>
    </div>`).join('');
}

function renderExploitConfirmation(el, cveIds, kevResp, epssResp, ghsaResp) {
  const kevOk = kevResp && kevResp.ok;
  const epssOk = epssResp && epssResp.ok;
  const ghsaOk = ghsaResp && ghsaResp.ok;
  if (!kevOk && !epssOk && !ghsaOk) {
    el.innerHTML = `<div class="live-cve-error">${escapeHtml(kevResp?.error || epssResp?.error || ghsaResp?.error || 'lookup failed')}</div>`;
    return;
  }
  const kevByCve = new Map((kevOk ? kevResp.matches : []).map(m => [m.cve.toUpperCase(), m]));
  const epssByCve = new Map((epssOk ? epssResp.results : []).map(r => [r.cve.toUpperCase(), r]));
  const ghsaByCve = new Map((ghsaOk ? ghsaResp.results : []).map(r => [r.cve.toUpperCase(), r]));

  const rows = cveIds.map(id => {
    const upper = id.toUpperCase();
    const kev = kevByCve.get(upper);
    const epss = epssByCve.get(upper);
    const ghsa = ghsaByCve.get(upper);
    const kevBadge = kev
      ? `<span class="exploit-badge exploit-kev">⚠ CISA KEV — confirmed actively exploited${kev.knownRansomwareCampaignUse === 'Known' ? ' (ransomware use known)' : ''}, added ${escapeHtml(kev.dateAdded || '?')}</span>`
      : (kevOk ? `<span class="exploit-badge exploit-none">not in CISA KEV</span>` : '');
    const epssBadge = epss
      ? `<span class="exploit-badge exploit-epss risk-${epss.risk}">EPSS ${(epss.epss * 100).toFixed(1)}% (${(epss.percentile * 100).toFixed(0)}th percentile) — ${epss.risk} predicted-exploitation risk</span>`
      : (epssOk ? `<span class="exploit-badge exploit-none">no EPSS score available</span>` : '');
    const ghsaBadge = ghsa && ghsa.advisories.length
      ? ghsa.advisories.map(a => `<span class="exploit-badge exploit-ghsa"><a href="${escapeHtml(a.htmlUrl)}" target="_blank" rel="noopener">${escapeHtml(a.ghsaId)}</a>${a.packages[0] ? ` — ${escapeHtml(a.packages[0].ecosystem || '')}:${escapeHtml(a.packages[0].name || '')}` : ''}</span>`).join(' ')
      : (ghsaOk ? `<span class="exploit-badge exploit-none">no GHSA advisory found</span>` : '');
    return `<div class="exploit-confirm-row"><span class="live-cve-id">${escapeHtml(id)}</span> ${kevBadge} ${epssBadge} ${ghsaBadge}</div>`;
  }).join('');

  el.innerHTML = rows;
}

function renderSecurity() {
  const panel = document.getElementById('securityPanel');
  const gradeEl = document.getElementById('secGrade');
  const checksEl = document.getElementById('securityChecks');
  const sec = currentResult?.security;
  if (!sec) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = '';
  gradeEl.textContent = sec.grade;
  gradeEl.className = `grade-badge grade-${sec.grade}`;
  checksEl.innerHTML = sec.checks.map(c => `
    <div class="sec-check">
      <span class="sec-status ${c.status}">${c.status}</span>
      <span class="sec-header-name">${escapeHtml(c.header)}:</span>
      <span class="sec-detail">${escapeHtml(c.detail)}</span>
    </div>`).join('');
}

// CVE IDs the user has explicitly confirmed via CISA KEV during this popup
// session (see the .confirm-exploit-btn handler below). Purely additive —
// this never triggers a KEV lookup itself, it only remembers ones the user
// already ran, so the risk score can reflect "confirmed actively exploited"
// once known rather than only ever seeing the unconfirmed CVE.
const kevConfirmedThisSession = new Set();

function renderRiskScore() {
  const row = document.getElementById('riskScoreRow');
  if (!currentResult) { row.classList.add('hidden'); return; }

  const result = computeRiskScore({
    security: currentResult.security || null,
    exposureFindings: currentResult.exposure?.findings || [],
    techFindings: currentResult.findings || [],
    kevConfirmedCveIds: [...kevConfirmedThisSession]
  });

  if (!result.hasData) { row.classList.add('hidden'); return; }
  row.classList.remove('hidden');

  const badge = document.getElementById('riskGradeBadge');
  badge.textContent = result.grade;
  badge.className = `grade-badge risk-grade-badge grade-${result.grade}`;
  document.getElementById('riskScoreValue').textContent = result.score;

  const breakdownEl = document.getElementById('riskBreakdown');
  breakdownEl.innerHTML = result.breakdown.length
    ? result.breakdown.map(b => `<div class="risk-breakdown-item"><span>${escapeHtml(b.label)}</span><span class="deduction">−${Math.round(b.deduction)}</span></div>`).join('')
    : `<div class="risk-breakdown-item"><span>No deductions — clean scan so far</span></div>`;
}

function renderExposure() {
  const resultsEl = document.getElementById('exposureResults');
  const exp = currentResult?.exposure;
  if (!exp) {
    resultsEl.innerHTML = '';
    return;
  }
  if (!exp.findings.length) {
    resultsEl.innerHTML = `<div class="exposure-clean">No exposure found as of ${new Date(exp.checkedAt).toLocaleTimeString()}.</div>`;
    return;
  }
  resultsEl.innerHTML = exp.findings.map(f => `
    <div class="exposure-item">
      <div class="exposure-title-row">
        <span class="exposure-sev ${f.severity}">${f.severity}</span>
        <span>${escapeHtml(f.title)}</span>
      </div>
      <div class="exposure-detail">${escapeHtml(f.detail)}</div>
    </div>`).join('');
}

function computeDiff(current, previous) {
  const curByName = new Map(current.map(f => [f.name, f]));
  const prevByName = new Map(previous.map(f => [f.name, f]));
  const changes = [];
  for (const [name, f] of curByName) {
    if (!prevByName.has(name)) {
      changes.push({ type: 'new', name, detail: f.version ? `v${f.version}` : 'detected' });
    } else {
      const p = prevByName.get(name);
      const versionChanged = (f.version || '') !== (p.version || '');
      const confidenceShift = Math.abs((f.confidence || 0) - (p.confidence || 0));
      if (versionChanged) {
        changes.push({ type: 'changed', name, detail: `v${p.version || '?'} → v${f.version || '?'}` });
      } else if (confidenceShift >= 20) {
        changes.push({ type: 'changed', name, detail: `confidence ${p.confidence} → ${f.confidence}` });
      }
    }
  }
  for (const [name] of prevByName) {
    if (!curByName.has(name)) changes.push({ type: 'removed', name, detail: 'no longer detected' });
  }
  return changes;
}

function renderDiff() {
  const btn = document.getElementById('btnDiff');
  if (!currentResult?.previous) {
    btn.classList.add('hidden');
    document.getElementById('diffPanel').classList.add('hidden');
    return;
  }
  const changes = computeDiff(currentResult.findings, currentResult.previous.findings);
  btn.classList.remove('hidden');
  btn.textContent = changes.length ? `Δ ${changes.length}` : 'Δ';
  document.getElementById('diffTitle').textContent = `Changes since ${new Date(currentResult.previous.scannedAt).toLocaleTimeString()}`;
  const listEl = document.getElementById('diffList');
  listEl.innerHTML = changes.length
    ? changes.map(c => `<div class="diff-item"><span class="diff-tag ${c.type}">${c.type}</span><span>${escapeHtml(c.name)}</span><span style="color:var(--text-muted)">${escapeHtml(c.detail)}</span></div>`).join('')
    : `<div class="diff-empty">No changes detected.</div>`;
}

function renderHeader() {
  document.getElementById('targetOrigin').textContent = currentResult?.origin || currentResult?.url || '—';
  document.getElementById('scanTime').textContent = fmtTime(currentResult?.scannedAt);
  const count = currentResult?.findings?.length || 0;
  document.getElementById('findingCount').textContent = `${count} technolog${count === 1 ? 'y' : 'ies'}`;
  const vulnCount = (currentResult?.findings || []).reduce((n, f) => n + (f.vulnerabilities?.length || 0), 0);
  const vulnEl = document.getElementById('vulnCount');
  if (vulnCount > 0) {
    vulnEl.textContent = `${vulnCount} flagged`;
    vulnEl.classList.remove('hidden');
  } else {
    vulnEl.classList.add('hidden');
  }
}

async function loadResults() {
  const resp = await chrome.runtime.sendMessage({ type: 'ISA_GET_RESULTS' });
  currentResult = resp?.result || null;
  renderHeader();
  renderDiff();
  renderSecurity();
  renderExposure();
  renderRiskScore();
  renderFilters(currentResult?.findings || []);
  renderResults();
}

document.getElementById('btnDiff').addEventListener('click', () => {
  document.getElementById('diffPanel').classList.toggle('hidden');
});
document.getElementById('closeDiff').addEventListener('click', () => {
  document.getElementById('diffPanel').classList.add('hidden');
});
document.getElementById('btnManageRules').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

document.getElementById('btnHistory').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('history/history.html') });
});

document.getElementById('btnScanAllTabs').addEventListener('click', async (e) => {
  const btn = e.target;
  const originalText = btn.textContent;
  btn.textContent = 'scanning…';
  btn.disabled = true;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'ISA_SCAN_ALL_TABS' });
    if (resp?.ok) {
      btn.textContent = resp.reloaded.length > 0
        ? `reloading ${resp.reloaded.length} unscanned tab${resp.reloaded.length === 1 ? '' : 's'}…`
        : `all ${resp.uniqueOrigins} open origin${resp.uniqueOrigins === 1 ? '' : 's'} already scanned ✓`;
    } else {
      btn.textContent = 'failed — try again';
    }
  } catch {
    btn.textContent = 'failed — try again';
  } finally {
    setTimeout(() => { btn.textContent = originalText; btn.disabled = false; }, 3000);
  }
});

document.getElementById('toggleSecDetail').addEventListener('click', () => {
  document.getElementById('securityChecks').classList.toggle('hidden');
});

document.getElementById('riskBreakdownToggle').addEventListener('click', () => {
  document.getElementById('riskBreakdown').classList.toggle('hidden');
});

document.getElementById('btnRunExposure').addEventListener('click', async (e) => {
  const btn = e.target;
  const originalText = btn.textContent;
  btn.textContent = 'scanning…';
  btn.disabled = true;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'ISA_RUN_EXPOSURE_CHECKS' });
    if (resp?.ok) {
      currentResult = currentResult || {};
      currentResult.exposure = { checkedAt: new Date().toISOString(), findings: resp.exposure };
      renderExposure();
      renderRiskScore();
    }
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
});

document.getElementById('btnRunGraphQL').addEventListener('click', async (e) => {
  const btn = e.target;
  const originalText = btn.textContent;
  btn.textContent = 'checking…';
  btn.disabled = true;
  let statusText = originalText;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'ISA_RUN_GRAPHQL_CHECK' });
    if (resp?.ok) {
      currentResult = currentResult || {};
      currentResult.exposure = currentResult.exposure || { checkedAt: new Date().toISOString(), findings: [] };
      currentResult.exposure.findings = [
        ...currentResult.exposure.findings.filter(f => !f.id.startsWith('graphql-introspection')),
        ...resp.findings
      ];
      renderExposure();
      renderRiskScore();
      statusText = resp.findings.length === 0 ? 'no introspection found ✓' : originalText;
    }
  } finally {
    btn.disabled = false;
    btn.textContent = statusText;
    if (statusText !== originalText) setTimeout(() => { btn.textContent = originalText; }, 2500);
  }
});

document.getElementById('btnRescan').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'ISA_RESCAN' });
  setTimeout(loadResults, 900);
});

document.getElementById('btnExport').addEventListener('click', () => {
  document.getElementById('exportMenu').classList.toggle('hidden');
});

document.getElementById('exportMenu').addEventListener('click', (e) => {
  const fmt = e.target.dataset.fmt;
  if (!fmt || !currentResult) return;
  let text, mime, ext;
  if (fmt === 'json') {
    text = JSON.stringify(currentResult, null, 2);
    mime = 'application/json'; ext = 'json';
  } else if (fmt === 'csv') {
    const rows = [['name', 'version', 'confidence', 'categories', 'verified', 'custom', 'inferred', 'versionConflict', 'cves']];
    for (const f of currentResult.findings) {
      rows.push([
        f.name, f.version || '', f.confidence, (f.categories || []).join('|'),
        f.verified ? 'yes' : 'no', f.custom ? 'yes' : 'no', f.inferred ? 'yes' : 'no',
        f.versionConflict ? (f.allVersionsFound || []).join('|') : '',
        (f.vulnerabilities || []).map(v => v.cve).join('|')
      ]);
    }
    // CSV/formula-injection protection (CWE-1236): version strings and
    // other fields here can be fully attacker-controlled — 13 technologies
    // read "version" directly from a live JS global with no restriction on
    // content (jQuery.fn.jquery, React.version, Sentry.SDK_VERSION, etc.),
    // so a page a researcher scans could set e.g. window.jQuery.fn.jquery
    // to a string starting with "=", which Excel/Sheets will interpret as
    // a formula on open regardless of normal CSV quote-escaping — that
    // escaping protects the CSV's own structure, not spreadsheet formula
    // interpretation, which is a different concern entirely. A leading
    // single quote is the standard mitigation: spreadsheet apps treat a
    // quote-prefixed cell as literal text.
    const sanitizeCsvField = (v) => {
      const s = String(v);
      return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
    };
    text = rows.map(r => r.map(v => `"${sanitizeCsvField(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    mime = 'text/csv'; ext = 'csv';
  } else if (fmt === 'sarif') {
    const doc = buildSarif({
      origin: currentResult.origin,
      scannedAt: currentResult.scannedAt,
      findings: currentResult.findings || [],
      exposureFindings: currentResult.exposure?.findings || [],
      securityChecks: currentResult.security?.checks || []
    });
    text = JSON.stringify(doc, null, 2);
    mime = 'application/sarif+json'; ext = 'sarif';
  } else {
    const lines = [`# ISA scan report`, ``, `**Target:** ${currentResult.origin}`, `**Scanned:** ${currentResult.scannedAt}`, ``];
    if (currentResult.security) {
      lines.push(`## Security headers — Grade ${currentResult.security.grade}`, '');
      for (const c of currentResult.security.checks) {
        lines.push(`- **${c.header}** (${c.status}): ${c.detail}`);
      }
      lines.push('');
    }
    if (currentResult.exposure?.findings?.length) {
      lines.push(`## Exposure checks`, '');
      for (const f of currentResult.exposure.findings) {
        lines.push(`- **[${f.severity}] ${f.title}**: ${f.detail}`);
      }
      lines.push('');
    }
    lines.push(`## Technologies`, '');
    for (const f of currentResult.findings) {
      lines.push(`## ${f.name}${f.version ? ` — v${f.version}` : ''}`);
      lines.push(`- Categories: ${(f.categories || []).join(', ') || 'n/a'}`);
      lines.push(`- Confidence: ${f.confidence}/100`);
      lines.push(`- Source: ${f.custom ? 'custom rule' : f.verified ? 'verified fingerprint' : f.inferred ? 'inferred' : 'imported/unverified'}`);
      if (f.versionConflict) {
        lines.push(`- ⚠ Version conflict: signals disagreed — versions found: ${f.allVersionsFound.join(', ')} (showing the highest-confidence one above)`);
      }
      if (f.vulnerabilities?.length) {
        lines.push(`- Flagged CVEs: ${f.vulnerabilities.map(v => v.cve).join(', ')}`);
      }
      lines.push('');
    }
    text = lines.join('\n');
    mime = 'text/markdown'; ext = 'md';
  }
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const origin = (currentResult.origin || 'isa-scan').replace(/[^a-z0-9.-]/gi, '_');
  chrome.downloads.download({ url, filename: `isa-scan-${origin}.${ext}` });
  document.getElementById('exportMenu').classList.add('hidden');
});

document.addEventListener('click', (e) => {
  const wrap = document.querySelector('.menu-wrap');
  if (!wrap.contains(e.target)) document.getElementById('exportMenu').classList.add('hidden');
});

loadResults();
