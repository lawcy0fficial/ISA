const STORAGE_KEY = 'isa_custom_rules';
const GPL_PACK_KEY = 'isa_enable_gpl_pack';
let rules = [];
let editingId = null;

function el(id) { return document.getElementById(id); }

async function loadGplPackToggle() {
  const stored = await chrome.storage.local.get(GPL_PACK_KEY);
  el('fGplPack').checked = !!stored[GPL_PACK_KEY];
}

el('fGplPack').addEventListener('change', async (e) => {
  await chrome.storage.local.set({ [GPL_PACK_KEY]: e.target.checked });
});

function num(id) {
  const v = el(id).value.trim();
  return v === '' ? undefined : parseInt(v, 10);
}
function str(id) {
  const v = el(id).value.trim();
  return v === '' ? undefined : v;
}

function buildSignalsFromForm() {
  const signals = {};

  if (str('hKey') && str('hRegex')) {
    signals.headers = [{ key: str('hKey'), regex: str('hRegex'), version: num('hVersionGroup'), confidence: num('hConfidence') || 30 }];
  }
  if (str('cRegex')) {
    signals.cookies = [{ regex: str('cRegex'), confidence: num('cConfidence') || 30 }];
  }
  if (str('mName') && str('mRegex')) {
    signals.meta = [{ name: str('mName'), regex: str('mRegex'), version: num('mVersionGroup'), confidence: num('mConfidence') || 30 }];
  }
  if (str('sRegex')) {
    signals.scriptSrc = [{ regex: str('sRegex'), version: num('sVersionGroup'), confidence: num('sConfidence') || 30 }];
  }
  if (str('ruRegex')) {
    signals.requestUrl = [{ regex: str('ruRegex'), version: num('ruVersionGroup'), confidence: num('ruConfidence') || 30 }];
  }
  if (str('tRegex')) {
    signals.html = [{ regex: str('tRegex'), confidence: num('tConfidence') || 30 }];
  }
  if (str('gPath')) {
    signals.globals = [{ path: str('gPath'), isVersionLike: el('gVersionLike').checked, confidence: num('gConfidence') || 30 }];
  }
  if (str('dSelector')) {
    signals.dom = [{ selector: str('dSelector'), confidence: num('dConfidence') || 20 }];
  }
  if (str('cvRegex')) {
    signals.cssVars = [{ regex: str('cvRegex'), confidence: num('cvConfidence') || 30 }];
  }
  if (str('cdRegex')) {
    signals.cspDomains = [{ regex: str('cdRegex'), confidence: num('cdConfidence') || 20 }];
  }
  return signals;
}

function clearForm() {
  el('ruleForm').reset();
  el('editId').value = '';
  editingId = null;
  el('formTitle').textContent = 'New rule';
  el('btnCancel').classList.add('hidden');
}

function populateForm(rule) {
  el('editId').value = rule.id;
  editingId = rule.id;
  el('fName').value = rule.name || '';
  el('fCategories').value = (rule.categories || []).join(', ');
  el('fWebsite').value = rule.website || '';
  el('fImplies').value = (rule.implies || []).join(', ');
  el('fVerified').checked = !!rule.verified;

  const s = rule.signals || {};
  const h = (s.headers || [])[0] || {};
  el('hKey').value = h.key || ''; el('hRegex').value = h.regex || '';
  el('hVersionGroup').value = h.version ?? ''; el('hConfidence').value = h.confidence ?? '';

  const c = (s.cookies || [])[0] || {};
  el('cRegex').value = c.regex || ''; el('cConfidence').value = c.confidence ?? '';

  const m = (s.meta || [])[0] || {};
  el('mName').value = m.name || ''; el('mRegex').value = m.regex || '';
  el('mVersionGroup').value = m.version ?? ''; el('mConfidence').value = m.confidence ?? '';

  const sc = (s.scriptSrc || [])[0] || {};
  el('sRegex').value = sc.regex || ''; el('sVersionGroup').value = sc.version ?? ''; el('sConfidence').value = sc.confidence ?? '';

  const ru = (s.requestUrl || [])[0] || {};
  el('ruRegex').value = ru.regex || ''; el('ruVersionGroup').value = ru.version ?? ''; el('ruConfidence').value = ru.confidence ?? '';

  const t = (s.html || [])[0] || {};
  el('tRegex').value = t.regex || ''; el('tConfidence').value = t.confidence ?? '';

  const g = (s.globals || [])[0] || {};
  el('gPath').value = g.path || ''; el('gVersionLike').checked = !!g.isVersionLike; el('gConfidence').value = g.confidence ?? '';

  const d = (s.dom || [])[0] || {};
  el('dSelector').value = d.selector || ''; el('dConfidence').value = d.confidence ?? '';

  const cv = (s.cssVars || [])[0] || {};
  el('cvRegex').value = cv.regex || ''; el('cvConfidence').value = cv.confidence ?? '';

  const cd = (s.cspDomains || [])[0] || {};
  el('cdRegex').value = cd.regex || ''; el('cdConfidence').value = cd.confidence ?? '';

  el('formTitle').textContent = `Editing: ${rule.name}`;
  el('btnCancel').classList.remove('hidden');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function signalSummary(rule) {
  const s = rule.signals || {};
  const parts = [];
  if (s.headers?.length) parts.push('header');
  if (s.cookies?.length) parts.push('cookie');
  if (s.meta?.length) parts.push('meta');
  if (s.scriptSrc?.length) parts.push('scriptSrc');
  if (s.requestUrl?.length) parts.push('requestUrl');
  if (s.html?.length) parts.push('html');
  if (s.globals?.length) parts.push('global');
  if (s.dom?.length) parts.push('dom');
  if (s.cssVars?.length) parts.push('cssVars');
  if (s.cspDomains?.length) parts.push('cspDomains');
  return parts.join(' + ') || 'no signals';
}

function renderList() {
  el('ruleCount').textContent = rules.length;
  const listEl = el('ruleList');
  if (!rules.length) {
    listEl.innerHTML = '<div class="empty">No custom rules yet — add one on the left.</div>';
    return;
  }
  listEl.innerHTML = rules.map(r => `
    <div class="rule-card" data-id="${r.id}">
      <div class="rule-card-head">
        <span class="rule-card-name">${escapeHtml(r.name)}</span>
        ${r.verified ? '<span class="rule-card-verified">verified</span>' : ''}
        <div class="rule-card-actions">
          <button data-action="edit">edit</button>
          <button data-action="delete">delete</button>
        </div>
      </div>
      <div class="rule-card-cats">${escapeHtml((r.categories || []).join(', ') || 'uncategorized')}</div>
      <div class="rule-card-signals">signals: ${signalSummary(r)}</div>
    </div>`).join('');

  listEl.querySelectorAll('.rule-card').forEach(card => {
    const id = card.dataset.id;
    card.querySelector('[data-action="edit"]').addEventListener('click', () => {
      const rule = rules.find(r => r.id === id);
      if (rule) populateForm(rule);
    });
    card.querySelector('[data-action="delete"]').addEventListener('click', async () => {
      rules = rules.filter(r => r.id !== id);
      await save();
      renderList();
      if (editingId === id) clearForm();
    });
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function load() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  rules = stored[STORAGE_KEY] || [];
  renderList();
}

async function save() {
  await chrome.storage.local.set({ [STORAGE_KEY]: rules });
}

function findInvalidRegexes(signals) {
  const bad = [];
  const collect = (list, label) => {
    for (const rule of list || []) {
      if (rule.regex === undefined) continue;
      try { new RegExp(rule.regex, 'i'); } catch (err) { bad.push(`${label} "${rule.regex}": ${err.message}`); }
    }
  };
  collect(signals.headers, 'header');
  collect(signals.cookies, 'cookie');
  collect(signals.meta, 'meta');
  collect(signals.scriptSrc, 'scriptSrc');
  collect(signals.requestUrl, 'requestUrl');
  collect(signals.html, 'html');
  collect(signals.cssVars, 'cssVars');
  collect(signals.cspDomains, 'cspDomains');
  if (signals.dom) {
    for (const rule of signals.dom) {
      if (rule.selector) {
        try { document.querySelector(rule.selector); } catch { bad.push(`DOM selector "${rule.selector}" is not a valid CSS selector`); }
      }
    }
  }
  return bad;
}

el('ruleForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = str('fName');
  if (!name) return;

  const signals = buildSignalsFromForm();
  if (Object.keys(signals).length === 0) {
    alert('Add at least one signal (header, cookie, meta, scriptSrc, requestUrl, html, global, DOM, cssVars, or cspDomains) — a rule with no signals can never match anything.');
    return;
  }

  const invalidRegexes = findInvalidRegexes(signals);
  if (invalidRegexes.length > 0) {
    alert(`This rule has invalid regex/selector syntax and can't be saved:\n\n${invalidRegexes.join('\n')}\n\nISA's matcher would silently skip a broken signal rather than crash, but it also means that signal could never match anything — fix the pattern before saving.`);
    return;
  }

  const rule = {
    id: editingId || `custom-${Date.now()}`,
    name,
    categories: (str('fCategories') || '').split(',').map(s => s.trim()).filter(Boolean),
    website: str('fWebsite') || null,
    implies: (str('fImplies') || '').split(',').map(s => s.trim()).filter(Boolean),
    verified: el('fVerified').checked,
    custom: true,
    signals
  };

  if (editingId) {
    rules = rules.map(r => (r.id === editingId ? rule : r));
  } else {
    rules.push(rule);
  }
  await save();
  renderList();
  clearForm();
});

el('btnCancel').addEventListener('click', clearForm);

load();
loadGplPackToggle();
