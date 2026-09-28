let rows = [];
let sortKey = 'scannedAt';
let sortDir = -1;

function el(id) { return document.getElementById(id); }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function loadAllScans() {
  const all = await chrome.storage.local.get(null);
  const scanKeys = Object.keys(all).filter(k => k.startsWith('scan:'));
  return scanKeys.map(k => {
    const r = all[k];
    const vulnCount = (r.findings || []).reduce((n, f) => n + (f.vulnerabilities?.length || 0), 0);
    return {
      origin: r.origin || k.slice(5),
      url: r.url,
      scannedAt: r.scannedAt,
      techCount: (r.findings || []).length,
      grade: r.security?.grade || '—',
      vulnCount,
      exposureCount: r.exposure?.findings?.length || 0,
      raw: r
    };
  });
}

function sortRows(list) {
  return [...list].sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (sortKey === 'scannedAt') { av = new Date(av).getTime(); bv = new Date(bv).getTime(); }
    if (typeof av === 'string') return sortDir * av.localeCompare(bv);
    return sortDir * ((av || 0) - (bv || 0));
  });
}

function render() {
  const query = el('search').value.trim().toLowerCase();
  const filtered = rows.filter(r => !query || r.origin.toLowerCase().includes(query));
  const sorted = sortRows(filtered);

  el('rowCount').textContent = `${sorted.length} origin${sorted.length === 1 ? '' : 's'}`;
  el('emptyState').classList.toggle('hidden', rows.length > 0);
  el('table').style.display = rows.length > 0 ? '' : 'none';

  el('tbody').innerHTML = sorted.map(r => `
    <tr>
      <td class="origin-cell">${escapeHtml(r.origin)}</td>
      <td class="time-cell">${r.scannedAt ? new Date(r.scannedAt).toLocaleString() : '—'}</td>
      <td>${r.techCount}</td>
      <td class="grade-cell grade-${r.grade}">${escapeHtml(r.grade)}</td>
      <td class="vuln-cell ${r.vulnCount > 0 ? 'nonzero' : ''}">${r.vulnCount}</td>
      <td>${r.exposureCount}</td>
    </tr>`).join('');
}

async function refresh() {
  rows = await loadAllScans();
  render();
}

document.querySelectorAll('thead th').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortKey === key) sortDir *= -1;
    else { sortKey = key; sortDir = key === 'scannedAt' ? -1 : 1; }
    render();
  });
});

el('search').addEventListener('input', render);

el('btnExportSummaryCsv').addEventListener('click', () => {
  // Defense-in-depth, not a confirmed exploit here the way the popup's
  // per-finding CSV export has one: every field in this summary export
  // (origin, an ISA-generated ISO date, an ISA-computed A-F grade, and
  // non-negative counts) is structurally incapable of starting with a
  // formula-triggering character today — a URL's own origin always
  // begins with a scheme like "https://". Added anyway so this stays
  // true if the row schema ever grows a field with less rigid structure,
  // and so this is the consistent house convention rather than something
  // to remember to add later under time pressure.
  const sanitizeCsvField = (v) => {
    const s = String(v);
    return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  };
  const header = ['origin', 'scannedAt', 'techCount', 'headerGrade', 'flaggedCves', 'exposureFindings'];
  const lines = [header.join(',')];
  for (const r of rows) {
    lines.push([r.origin, r.scannedAt, r.techCount, r.grade, r.vulnCount, r.exposureCount]
      .map(v => `"${sanitizeCsvField(v).replace(/"/g, '""')}"`).join(','));
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  chrome.downloads.download({ url: URL.createObjectURL(blob), filename: `isa-history-summary-${Date.now()}.csv` });
});

el('btnExportAllJson').addEventListener('click', () => {
  const combined = rows.map(r => r.raw);
  const blob = new Blob([JSON.stringify(combined, null, 2)], { type: 'application/json' });
  chrome.downloads.download({ url: URL.createObjectURL(blob), filename: `isa-history-full-${Date.now()}.json` });
});

el('btnClear').addEventListener('click', async () => {
  if (!confirm(`Delete all ${rows.length} stored scan(s)? This can't be undone.`)) return;
  const all = await chrome.storage.local.get(null);
  const scanKeys = Object.keys(all).filter(k => k.startsWith('scan:'));
  await chrome.storage.local.remove(scanKeys);
  await refresh();
});

refresh();
