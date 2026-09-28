/**
 * ISA background service worker.
 * Aggregates every evidence source per tab, runs the matching engine once
 * all sources have reported in (or a short debounce elapses), and persists
 * results to chrome.storage.local keyed by origin.
 */

importScripts('lib/matcher.js', 'lib/security-headers.js', 'lib/exposure-checks.js', 'lib/live-cve-lookup.js', 'lib/exploit-links.js', 'lib/kev-lookup.js', 'lib/epss-lookup.js', 'lib/ghsa-lookup.js', 'lib/osv-lookup.js', 'lib/bulk-scan.js', 'lib/cpe-lookup.js');

const RULESET_URL = chrome.runtime.getURL('lib/technologies.json');
const VULNDB_URL = chrome.runtime.getURL('lib/vuln-db.json');
const FAVICONDB_URL = chrome.runtime.getURL('lib/favicon-hashes.json');
const GPL_PACK_URL = chrome.runtime.getURL('lib/technologies-gpl-extended.json');

let ruleset = null;
let vulnDb = null;
let faviconDb = null;
let gplPack = null;
let lastNvdRequestAt = 0;

async function loadData() {
  if (!ruleset) ruleset = await fetch(RULESET_URL).then(r => r.json());
  if (!vulnDb) vulnDb = await fetch(VULNDB_URL).then(r => r.json());
  if (!faviconDb) faviconDb = await fetch(FAVICONDB_URL).then(r => r.json());
}

// tabId -> partial evidence accumulator
const tabState = new Map();

function getState(tabId) {
  if (!tabState.has(tabId)) {
    tabState.set(tabId, {
      headers: {},
      setCookieHeaders: [],
      cookies: [],
      metaTags: [],
      scriptSrcs: [],
      subresources: [],
      htmlSample: '',
      dom: { matchedSelectors: [], attrs: [] },
      globals: {},
      faviconHash: null,
      origin: null,
      url: null,
      requestUrls: [],
      cssVars: [],
      cspDomains: [],
      debounce: null
    });
  }
  return tabState.get(tabId);
}

// ---- webRequest: capture response headers for the main document -------

// Extracts hostnames from a Content-Security-Policy header's directives
// (script-src, connect-src, frame-src, img-src, style-src, font-src). A
// domain listed here is weaker evidence than one actually observed in a
// request or script tag — it's what the site *permits*, not necessarily
// what it *uses* — which is why this feeds a separately-weighted signal
// type (cspDomains) rather than being folded into requestUrls/scriptSrc.
function extractCspDomains(cspHeader) {
  if (!cspHeader) return [];
  const domains = new Set();
  const directivesOfInterest = /(?:script-src|connect-src|frame-src|img-src|style-src|font-src)\s+([^;]+)/gi;
  let dirMatch;
  while ((dirMatch = directivesOfInterest.exec(cspHeader))) {
    const tokens = dirMatch[1].trim().split(/\s+/);
    for (const token of tokens) {
      // skip keywords ('self', 'unsafe-inline', nonces, hashes) and schemes
      if (token.startsWith("'") || token === '*' || /^[a-z]+:$/.test(token)) continue;
      const hostMatch = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(\*\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i.exec(token);
      if (hostMatch) domains.add(hostMatch[2].toLowerCase());
    }
  }
  return [...domains].slice(0, 100); // bounded
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame' || details.tabId < 0) return;
    const state = getState(details.tabId);
    const headers = {};
    const setCookieHeaders = [];
    for (const h of details.responseHeaders || []) {
      const name = h.name.toLowerCase();
      if (name === 'set-cookie' && h.value) setCookieHeaders.push(h.value);
      headers[name] = h.value || '';
    }
    state.headers = headers;
    state.setCookieHeaders = setCookieHeaders;
    state.cspDomains = extractCspDomains(headers['content-security-policy']);
    state.url = details.url;
    try { state.origin = new URL(details.url).origin; } catch { /* ignore */ }
    scheduleEvaluation(details.tabId);
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders', 'extraHeaders']
);

// separate, lighter-weight listener: capture XHR/fetch/WebSocket endpoint
// URLs (not full headers) so API- and real-time-technology signatures
// (GraphQL endpoints, WordPress REST API, Socket.io/Pusher/Firebase
// WebSocket connections, third-party SaaS APIs) can match against real
// observed traffic rather than static page markup alone.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (details.type !== 'xmlhttprequest' && details.type !== 'other' && details.type !== 'websocket') return;
    const state = getState(details.tabId);
    if (state.requestUrls.length >= 300) return; // bounded, avoid unbounded growth on long-lived SPA tabs
    if (!state.requestUrls.includes(details.url)) {
      state.requestUrls.push(details.url);
      scheduleEvaluation(details.tabId);
    }
  },
  { urls: ['<all_urls>'], types: ['xmlhttprequest', 'other', 'websocket'] }
);

// reset accumulated state on a fresh top-level navigation
chrome.webNavigation.onCommitted?.addListener?.((details) => {
  if (details.frameId === 0) tabState.delete(details.tabId);
});

// tabState is only ever cleared on same-tab navigation or manual rescan —
// without this, closing a tab leaves its entry (headers, cookies, up to
// 400 script srcs, 300 request URLs, ~50KB of HTML sample, etc.) sitting
// in memory for as long as the service worker instance stays alive. MV3
// workers do get torn down after ~30s idle (which would incidentally
// clear this), but during an active session with frequent events keeping
// the worker alive, this can accumulate across many opened-and-closed
// tabs — worth cleaning up properly rather than relying on the worker
// lifecycle to paper over it.
chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

// SPA route changes (pushState/replaceState) don't trigger a document
// reload — the page's headers/cookies from the original document load are
// still valid, but DOM/meta/script/global evidence needs to be recollected
// against the new virtual URL. This is what lets ISA stay accurate on
// React/Next.js/Vue-router style apps instead of only ever reflecting
// whatever route the user first landed on.
chrome.webNavigation.onHistoryStateUpdated?.addListener?.((details) => {
  if (details.frameId !== 0) return;
  const state = getState(details.tabId);
  state.url = details.url;
  try { state.origin = new URL(details.url).origin; } catch { /* keep previous origin */ }
  chrome.tabs.sendMessage(details.tabId, { type: 'ISA_REQUEST_RESCAN' }).catch(() => {});
  enrichGlobals(details.tabId); // re-probe live globals — a new route may have mounted new libraries
  enrichDomSelectors(details.tabId); // same reasoning — a new route may have mounted new DOM elements
});

// ---- content script messages -------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'ISA_PAGE_EVIDENCE' && sender.tab) {
    const tabId = sender.tab.id;
    const state = getState(tabId);
    state.metaTags = msg.metaTags || [];
    state.scriptSrcs = msg.scriptSrcs || [];
    state.subresources = msg.subresources || [];
    state.cssVars = msg.cssVars || [];
    state.htmlSample = msg.htmlSample || '';
    state.dom = msg.dom || { matchedSelectors: [], attrs: [] };
    state.cookies = (msg.cookiesRaw || '').split(';').map(c => c.split('=')[0].trim()).filter(Boolean);
    state.url = msg.url;
    state.origin = msg.origin;

    // fire-and-forget: enrich with real HTTP cookies (incl. HttpOnly), favicon
    // hash, page-global probe, and dynamic DOM selector matching (see
    // enrichDomSelectors — the ruleset's dom selectors are checked live
    // against the real DOM rather than a static watchlist that drifts out
    // of sync every time a new dom-based signal is added to the ruleset).
    enrichCookies(tabId, msg.origin);
    enrichFavicon(tabId, msg.faviconUrl);
    enrichGlobals(tabId);
    enrichDomSelectors(tabId);

    scheduleEvaluation(tabId);
  }

  if (msg?.type === 'ISA_GET_RESULTS') {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return sendResponse({ ok: false });
      const origin = tab.url ? new URL(tab.url).origin : null;
      const stored = origin ? (await chrome.storage.local.get(`scan:${origin}`))[`scan:${origin}`] : null;
      sendResponse({ ok: true, origin, url: tab.url, result: stored || null });
    })();
    return true; // async response
  }

  if (msg?.type === 'ISA_SCAN_ALL_TABS') {
    // Reloads only tabs ISA has never scanned (no scan:<origin> entry yet)
    // — never a tab that already has results, so this can't clobber a
    // scan the user already looked at, and never a tab that isn't
    // http(s) (chrome://, extension pages, etc. are skipped outright).
    // This is the only way to populate results for a tab that isn't the
    // currently active one: ISA's header/cookie evidence comes from a
    // webRequest listener tied to page navigation (see the top-of-file
    // note on that), so there's no way to scan a tab without it loading —
    // reloading unscanned tabs is the honest way to do "scan everything
    // open" rather than silently doing nothing for tabs never visited
    // through this popup.
    (async () => {
      const tabs = await chrome.tabs.query({});
      const httpTabs = tabs.filter(t => t.url && /^https?:\/\//.test(t.url));
      const origins = [...new Set(httpTabs.map(t => { try { return new URL(t.url).origin; } catch { return null; } }).filter(Boolean))];
      const storageKeys = origins.map(o => `scan:${o}`);
      const stored = storageKeys.length ? await chrome.storage.local.get(storageKeys) : {};
      const scannedOrigins = new Set(origins.filter(o => stored[`scan:${o}`]));

      const { httpTabCount, uniqueOrigins, toReload } = selectTabsToReload(tabs, scannedOrigins);

      for (const { tabId } of toReload) {
        chrome.tabs.reload(tabId).catch(() => { /* tab may have closed between query and reload — not fatal */ });
      }

      sendResponse({
        ok: true,
        totalHttpTabs: httpTabCount,
        uniqueOrigins: uniqueOrigins.length,
        alreadyScanned: uniqueOrigins.length - toReload.length,
        reloaded: toReload.map(t => t.origin)
      });
    })();
    return true;
  }

  if (msg?.type === 'ISA_RESCAN') {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return sendResponse({ ok: false });
      tabState.delete(tab.id);
      await chrome.tabs.reload(tab.id);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.type === 'ISA_RUN_EXPOSURE_CHECKS') {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) return sendResponse({ ok: false, error: 'no active tab' });
      let origin;
      try { origin = new URL(tab.url).origin; } catch { return sendResponse({ ok: false, error: 'unsupported URL' }); }

      const state = getState(tab.id);
      const exposure = await runExposureChecks(origin, state.scriptSrcs);

      const key = `scan:${origin}`;
      const stored = (await chrome.storage.local.get(key))[key];
      if (stored) {
        stored.exposure = { checkedAt: new Date().toISOString(), findings: exposure };
        await chrome.storage.local.set({ [key]: stored });
      }
      sendResponse({ ok: true, exposure });
    })();
    return true;
  }

  if (msg?.type === 'ISA_RUN_GRAPHQL_CHECK') {
    // Separate opt-in action from ISA_RUN_EXPOSURE_CHECKS — see the
    // comment on runGraphQLCheck in lib/exposure-checks.js for why this
    // isn't bundled into the default exposure-check batch.
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) return sendResponse({ ok: false, error: 'no active tab' });
      let origin;
      try { origin = new URL(tab.url).origin; } catch { return sendResponse({ ok: false, error: 'unsupported URL' }); }

      const findings = await runGraphQLCheck(origin);

      const key = `scan:${origin}`;
      const stored = (await chrome.storage.local.get(key))[key];
      if (stored && findings.length) {
        stored.exposure = stored.exposure || { checkedAt: new Date().toISOString(), findings: [] };
        stored.exposure.findings = [...stored.exposure.findings.filter(f => !f.id.startsWith('graphql-introspection')), ...findings];
        await chrome.storage.local.set({ [key]: stored });
      }
      sendResponse({ ok: true, findings });
    })();
    return true;
  }

  if (msg?.type === 'ISA_CHECK_LIVE_CVE') {
    (async () => {
      const { techName, version } = msg;
      if (!techName) return sendResponse({ ok: false, error: 'missing technology name' });

      const cacheKey = `nvdCache:${techName}:${version || ''}`;
      const cached = (await chrome.storage.local.get(cacheKey))[cacheKey];
      const CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12h — NVD data doesn't change minute-to-minute
      if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
        return sendResponse({ ...cached.result, cached: true });
      }

      // simple client-side pacing so we don't hammer NVD's public rate limit
      // (a handful of requests per 30s without an API key)
      const now = Date.now();
      const waitMs = Math.max(0, lastNvdRequestAt + 6500 - now);
      if (waitMs > 0) await new Promise(r => setTimeout(r, waitMs));
      lastNvdRequestAt = Date.now();

      const result = await queryLiveCves(techName, version);
      if (result.ok) {
        result.results = result.results.map(r => ({ ...r, links: buildReferenceLinks(r.id) }));
        await chrome.storage.local.set({ [cacheKey]: { fetchedAt: Date.now(), result } });
      }
      sendResponse({ ...result, cached: false });
    })();
    return true;
  }

  if (msg?.type === 'ISA_CHECK_KEV') {
    // "Confirming exploits" the only way that fits ISA's rules: cross-
    // referencing CVE IDs ISA already found against CISA's authoritative,
    // continuously-updated list of vulnerabilities confirmed to be
    // actively exploited in the wild right now — not running anything
    // against the target. See lib/kev-lookup.js for the full rationale.
    (async () => {
      const { cveIds } = msg;
      if (!Array.isArray(cveIds) || cveIds.length === 0) {
        return sendResponse({ ok: false, error: 'missing cveIds' });
      }

      const CACHE_KEY = 'kevCatalogCache';
      const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h — CISA updates KEV multiple times/week, not minute-to-minute
      const cached = (await chrome.storage.local.get(CACHE_KEY))[CACHE_KEY];
      let catalog;
      if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
        catalog = cached.catalog;
      } else {
        const fetched = await fetchKevCatalog();
        if (!fetched.ok) {
          // fall back to a stale cached catalog rather than failing outright,
          // if one exists — better a slightly-stale KEV check than none
          if (cached) { catalog = cached.catalog; }
          else return sendResponse({ ok: false, error: fetched.error });
        } else {
          catalog = fetched;
          try {
            await chrome.storage.local.set({ [CACHE_KEY]: { fetchedAt: Date.now(), catalog } });
          } catch { /* quota edge case — still usable for this session */ }
        }
      }

      const matches = crossReferenceKev(cveIds, catalog);
      sendResponse({ ok: true, catalogVersion: catalog.catalogVersion || null, matches });
    })();
    return true;
  }

  if (msg?.type === 'ISA_CHECK_EPSS') {
    // Complementary to KEV: a statistical 30-day exploitation-probability
    // score per CVE, for prioritizing the ones that haven't been confirmed
    // exploited (yet) but are trending likely to be. See lib/epss-lookup.js.
    (async () => {
      const { cveIds } = msg;
      if (!Array.isArray(cveIds) || cveIds.length === 0) {
        return sendResponse({ ok: false, error: 'missing cveIds' });
      }
      const result = await queryEpssScores(cveIds);
      sendResponse(result);
    })();
    return true;
  }

  if (msg?.type === 'ISA_CHECK_GHSA') {
    // Third correlation source: GitHub's own advisory database, which
    // covers npm/pip/etc. package ecosystems ISA's ruleset mostly lives
    // in, sometimes faster or more precisely than NVD. See lib/ghsa-lookup.js.
    (async () => {
      const { cveIds } = msg;
      if (!Array.isArray(cveIds) || cveIds.length === 0) {
        return sendResponse({ ok: false, error: 'missing cveIds' });
      }
      const result = await queryGhsaAdvisories(cveIds);
      sendResponse(result);
    })();
    return true;
  }

  if (msg?.type === 'ISA_CHECK_OSV') {
    // Structurally different from KEV/EPSS/GHSA: queries by package name +
    // version rather than by CVE ID, so this can surface a vulnerability
    // for any detected+versioned technology ISA has a package mapping for
    // — not just the 12 currently in vuln-db.json. See lib/osv-lookup.js.
    (async () => {
      const { techName, version } = msg;
      if (!techName) return sendResponse({ ok: false, error: 'missing technology name' });
      const result = await queryOsvForFinding(techName, version);
      sendResponse(result);
    })();
    return true;
  }

  if (msg?.type === 'ISA_CHECK_CPE_MATCH') {
    // Experimental — see the honesty note at the top of lib/cpe-lookup.js.
    // Precise CPE-based NVD matching for a small curated set of
    // technologies, as an alternative to the fuzzy keywordSearch used by
    // ISA_CHECK_LIVE_CVE.
    (async () => {
      const { techName, version } = msg;
      if (!techName) return sendResponse({ ok: false, error: 'missing technology name' });
      const result = await queryCpeMatch(techName, version);
      sendResponse(result);
    })();
    return true;
  }
});

async function enrichCookies(tabId, origin) {
  if (!origin) return;
  try {
    const cookies = await chrome.cookies.getAll({ url: origin });
    const state = getState(tabId);
    const names = new Set(state.cookies);
    for (const c of cookies) names.add(c.name);
    state.cookies = [...names];
    scheduleEvaluation(tabId);
  } catch { /* cookies permission edge cases (e.g. chrome:// pages) */ }
}

async function enrichFavicon(tabId, faviconUrl) {
  if (!faviconUrl) return;
  try {
    const resp = await fetch(faviconUrl);
    if (!resp.ok) return;
    const buf = await resp.arrayBuffer();
    if (buf.byteLength === 0) return;
    const digest = await crypto.subtle.digest('SHA-256', buf);
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
    getState(tabId).faviconHash = hex;
  } catch { /* favicon may be missing or blocked by CORS for hashing of opaque response */ }
}

// Executed in the page's MAIN world to read real global object values —
// content scripts run in an isolated world and can't see page globals.
function probeGlobals() {
  function safeGet(getter) {
    try { return getter(); } catch { return undefined; }
  }
  const out = {};
  out['jQuery.fn.jquery'] = safeGet(() => window.jQuery.fn.jquery);
  out['React.version'] = safeGet(() => window.React.version);
  out['Vue.version'] = safeGet(() => window.Vue.version);
  out['getAllAngularRootElements'] = safeGet(() => (typeof window.getAllAngularRootElements === 'function' ? 'present' : undefined));
  out['Shopify.shop'] = safeGet(() => window.Shopify.shop);
  out['Shopify.theme.name'] = safeGet(() => window.Shopify.theme.name);
  out['gtag'] = safeGet(() => (typeof window.gtag === 'function' ? 'present' : undefined));
  out['google_tag_manager'] = safeGet(() => (window.google_tag_manager ? 'present' : undefined));
  out['Stripe'] = safeGet(() => (typeof window.Stripe === 'function' ? 'present' : undefined));
  out['Sentry.SDK_VERSION'] = safeGet(() => window.Sentry.SDK_VERSION);
  out['_.VERSION'] = safeGet(() => window._.VERSION);
  out['moment.version'] = safeGet(() => window.moment.version);
  out['gsap.version'] = safeGet(() => window.gsap.version);
  out['__APOLLO_CLIENT__'] = safeGet(() => (window.__APOLLO_CLIENT__ ? 'present' : undefined));
  out['Ember.VERSION'] = safeGet(() => window.Ember.VERSION);
  out['Alpine.version'] = safeGet(() => window.Alpine.version);
  out['Backbone.VERSION'] = safeGet(() => window.Backbone.VERSION);
  out['Intercom'] = safeGet(() => (typeof window.Intercom === 'function' ? 'present' : undefined));
  out['optimizely'] = safeGet(() => (Array.isArray(window.optimizely) ? 'present' : undefined));
  out['LDClient'] = safeGet(() => (window.LDClient ? 'present' : undefined));
  out['Optanon'] = safeGet(() => (typeof window.Optanon === 'object' ? 'present' : undefined));
  out['PDFJS.version'] = safeGet(() => window.PDFJS.version);
  out['paypal'] = safeGet(() => (window.paypal ? 'present' : undefined));
  out['PIXI.VERSION'] = safeGet(() => window.PIXI.VERSION);
  out['PARSELY'] = safeGet(() => (window.PARSELY ? 'present' : undefined));
  out['partytown'] = safeGet(() => (window.partytown ? 'present' : undefined));
  out['adyen.encrypt.version'] = safeGet(() => window.adyen.encrypt.version);
  out['addthis'] = safeGet(() => (window.addthis ? 'present' : undefined));
  out['a2apage_init'] = safeGet(() => (typeof window.a2apage_init === 'function' ? 'present' : undefined));
  out['ActOn'] = safeGet(() => (window.ActOn ? 'present' : undefined));
  out['ados'] = safeGet(() => (window.ados ? 'present' : undefined));
  out['s_c_il.0._c'] = safeGet(() => window.s_c_il && window.s_c_il[0] && window.s_c_il[0]._c);
  out['NREUM'] = safeGet(() => (window.NREUM ? 'present' : undefined));
  out['Bugsnag'] = safeGet(() => (window.Bugsnag ? 'present' : undefined));
  out['Clerk'] = safeGet(() => (window.Clerk ? 'present' : undefined));
  out['posthog'] = safeGet(() => (window.posthog ? 'present' : undefined));
  out['heap'] = safeGet(() => (window.heap ? 'present' : undefined));
  out['fbq'] = safeGet(() => (typeof window.fbq === 'function' ? 'present' : undefined));
  out['THREE.REVISION'] = safeGet(() => window.THREE.REVISION);
  out['Chart.version'] = safeGet(() => window.Chart.version);
  out['L.version'] = safeGet(() => window.L.version);
  out['mapboxgl.version'] = safeGet(() => window.mapboxgl.version);
  out['Swiper.version'] = safeGet(() => window.Swiper.version);
  out['CKEDITOR.version'] = safeGet(() => window.CKEDITOR.version);
  out['tinymce.majorVersion'] = safeGet(() => window.tinymce.majorVersion);
  out['LogRocket'] = safeGet(() => (window.LogRocket ? 'present' : undefined));
  out['d3.version'] = safeGet(() => window.d3.version);
  out['Highcharts.version'] = safeGet(() => window.Highcharts.version);
  out['Wistia'] = safeGet(() => (window.Wistia ? 'present' : undefined));
  out['jwplayer.version'] = safeGet(() => window.jwplayer.version);
  out['initGeetest'] = safeGet(() => (typeof window.initGeetest === 'function' ? 'present' : undefined));
  out['tidioChatApi'] = safeGet(() => (window.tidioChatApi ? 'present' : undefined));
  out['TrackJS.version'] = safeGet(() => window.TrackJS.version);
  out['jQuery.ui.version'] = safeGet(() => window.jQuery.ui.version);
  return out;
}
async function enrichGlobals(tabId) {
  try {
    const [{ result } = {}] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: probeGlobals
    });
    if (result) {
      const state = getState(tabId);
      state.globals = result;
      scheduleEvaluation(tabId);
    }
  } catch { /* restricted pages (chrome://, Web Store) reject injection */ }
}

// Checks the ruleset's actual dom.selector values live against the page's
// real DOM, executed in the page's own document — not a hand-maintained
// watchlist in content-script.js, which is exactly what silently broke
// DOM-based detection for React, Vue, hCaptcha, PWA, Partytown, Patreon,
// and YouTube Embed for as long as this project has had DOM-based rules:
// the watchlist was never updated when a new dom-signal entry was added,
// so those selectors were checked against nothing and could never match.
// A CSS selector-list string like "[data-reactroot], #__next" is valid
// querySelector syntax on its own (matches if *either* half matches), so
// using the ruleset's rule.selector verbatim as both the query and the
// stored match-key keeps this self-consistent by construction — no more
// two separate lists that can drift apart.
async function enrichDomSelectors(tabId) {
  try {
    await loadData();
    const customWrap = await chrome.storage.local.get('isa_custom_rules');
    const customRules = customWrap.isa_custom_rules || [];
    const gplPackWrap = await chrome.storage.local.get('isa_enable_gpl_pack');
    let gplTechs = [];
    if (gplPackWrap.isa_enable_gpl_pack) {
      if (!gplPack) gplPack = await fetch(GPL_PACK_URL).then(r => r.json());
      gplTechs = gplPack.technologies;
    }
    const selectors = new Set();
    for (const tech of [...ruleset.technologies, ...gplTechs, ...customRules]) {
      for (const d of (tech.signals?.dom || [])) {
        if (d.selector) selectors.add(d.selector);
      }
    }
    if (selectors.size === 0) return;

    const [{ result } = {}] = await chrome.scripting.executeScript({
      target: { tabId },
      func: (sels) => sels.filter(sel => {
        try { return document.querySelector(sel) !== null; } catch { return false; }
      }),
      args: [[...selectors]]
    });
    if (result) {
      const state = getState(tabId);
      state.dom = state.dom || { matchedSelectors: [], attrs: [] };
      state.dom.matchedSelectors = result;
      scheduleEvaluation(tabId);
    }
  } catch { /* restricted pages reject injection, same constraint as enrichGlobals */ }
}

// ---- debounce + evaluate -------------------------------------------------

function scheduleEvaluation(tabId) {
  const state = getState(tabId);
  clearTimeout(state.debounce);
  state.debounce = setTimeout(() => evaluateTab(tabId), 350);
}

// ---- storage hygiene ------------------------------------------------
// Every scanned origin gets a permanent scan:<origin> key with no built-in
// expiration, and NVD cache entries similarly accumulate — chrome.storage.local
// has a real quota (10MB by default, no unlimitedStorage permission
// requested here deliberately, since that would need its own disclosure).
// For a tool meant for extended professional use — scanning many targets
// over an engagement — that adds up. Cleanup runs opportunistically after
// a scan write, throttled to at most once per hour so it doesn't add a
// full chrome.storage.local.get(null) read to every single page scan.

const MAX_SCAN_ENTRIES = 500;
const CLEANUP_THROTTLE_MS = 60 * 60 * 1000; // 1 hour
const NVD_CACHE_TTL_MS = 12 * 60 * 60 * 1000; // matches the cache-read TTL used elsewhere

async function maybeRunStorageCleanup() {
  const throttleKey = 'isa_last_cleanup_at';
  const stored = await chrome.storage.local.get(throttleKey);
  const lastRun = stored[throttleKey] || 0;
  if (Date.now() - lastRun < CLEANUP_THROTTLE_MS) return;
  await chrome.storage.local.set({ [throttleKey]: Date.now() });

  try {
    const all = await chrome.storage.local.get(null);
    const now = Date.now();

    // prune expired NVD cache entries outright — a TTL that's only ever
    // checked on read still leaves the stale entry consuming quota forever
    // if that technology+version is never looked up again.
    const expiredNvdKeys = Object.keys(all)
      .filter(k => k.startsWith('nvdCache:') && all[k]?.fetchedAt && now - all[k].fetchedAt > NVD_CACHE_TTL_MS);
    if (expiredNvdKeys.length) await chrome.storage.local.remove(expiredNvdKeys);

    // cap total scan entries — evict oldest-scanned origins first once
    // over the limit, so long-running use degrades gracefully instead of
    // eventually hitting the quota with no warning.
    const scanEntries = Object.keys(all)
      .filter(k => k.startsWith('scan:'))
      .map(k => ({ key: k, scannedAt: all[k]?.scannedAt || '' }))
      .sort((a, b) => a.scannedAt.localeCompare(b.scannedAt)); // oldest first
    if (scanEntries.length > MAX_SCAN_ENTRIES) {
      const toEvict = scanEntries.slice(0, scanEntries.length - MAX_SCAN_ENTRIES).map(e => e.key);
      await chrome.storage.local.remove(toEvict);
    }
  } catch {
    // best-effort — a failed cleanup pass just means we try again next
    // throttle window, never worth breaking a scan over.
  }
}

async function evaluateTab(tabId) {
  await loadData();
  const state = getState(tabId);
  if (!state.origin) return;

  const customWrap = await chrome.storage.local.get('isa_custom_rules');
  const customRules = customWrap.isa_custom_rules || [];

  // GPL-3.0 extended pack — opt-in only, off by default. Enabling it merges
  // in a separately-licensed technology set; see GPL-PACK-NOTICE.md. This
  // is checked fresh each scan (not cached alongside ruleset/vulnDb) since
  // it's a user preference that can change at any time via the options page.
  const gplPackWrap = await chrome.storage.local.get('isa_enable_gpl_pack');
  let gplTechs = [];
  if (gplPackWrap.isa_enable_gpl_pack) {
    if (!gplPack) gplPack = await fetch(GPL_PACK_URL).then(r => r.json());
    const coreNames = new Set(ruleset.technologies.map(t => t.name));
    // defensive: never let a GPL-pack entry silently shadow a core MIT
    // entry of the same name — skip any collision rather than guess which
    // should win.
    gplTechs = gplPack.technologies.filter(t => !coreNames.has(t.name));
  }

  const combinedRuleset = (customRules.length || gplTechs.length)
    ? { ...ruleset, technologies: [...ruleset.technologies, ...gplTechs, ...customRules] }
    : ruleset;

  const evidence = {
    headers: state.headers,
    cookies: state.cookies,
    metaTags: state.metaTags,
    scriptSrcs: state.scriptSrcs,
    cssVars: state.cssVars,
    cspDomains: state.cspDomains,
    requestUrls: state.requestUrls,
    htmlSample: state.htmlSample,
    globals: state.globals,
    dom: state.dom,
    faviconHash: state.faviconHash
  };

  const findings = evaluate(evidence, combinedRuleset, vulnDb, faviconDb);
  const isHttps = (state.url || '').startsWith('https://');
  const security = gradeHeaders(state.headers, state.setCookieHeaders, isHttps, state.subresources);

  const result = {
    origin: state.origin,
    url: state.url,
    scannedAt: new Date().toISOString(),
    findings,
    security
  };

  const key = `scan:${state.origin}`;
  const prevWrap = await chrome.storage.local.get(key);
  const prev = prevWrap[key];
  if (prev) {
    result.previous = { scannedAt: prev.scannedAt, findings: prev.findings };
    if (prev.exposure) result.exposure = prev.exposure; // carry forward opt-in scan results across passive rescans
  }

  let persisted = true;
  try {
    await chrome.storage.local.set({ [key]: result });
  } catch (err) {
    // most likely QUOTA_BYTES_PER_ITEM or total quota exceeded. Don't let
    // a storage failure silently swallow the whole scan — the badge still
    // reflects what was found even if it couldn't be persisted for the
    // popup/history to read later, and a cleanup pass gets a chance to
    // free space before the next scan.
    persisted = false;
    console.warn('ISA: failed to persist scan result, will retry cleanup on next scan:', err.message);
  }
  maybeRunStorageCleanup(); // fire-and-forget; throttled internally, never blocks the scan

  const vulnCount = findings.reduce((n, f) => n + (f.vulnerabilities?.length || 0), 0);
  await chrome.action.setBadgeText({ tabId, text: findings.length ? String(findings.length) : '' });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: !persisted ? '#8891a3' : vulnCount > 0 ? '#e5484d' : '#ffb03b' });
}
