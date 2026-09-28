/**
 * ISA — bulk-scan tab selection.
 *
 * Pure decision logic extracted out of the ISA_SCAN_ALL_TABS message
 * handler in background.js specifically so it's unit-testable without a
 * real chrome.tabs/chrome.storage environment — the actual chrome API
 * calls stay in background.js, this file only decides *which* tabs
 * should be reloaded given the inputs.
 *
 * Rules, each load-bearing for why "scan all tabs" is safe to run without
 * a per-tab confirmation prompt:
 *   1. Only http(s) tabs are ever considered — chrome://, extension
 *      pages, file:// etc. are never touched.
 *   2. A tab whose origin already has a stored scan result is NEVER
 *      reloaded — this can only ever add new results, never clobber one
 *      the user already looked at.
 *   3. At most one tab is reloaded per unscanned origin — five tabs open
 *      on the same site produce one reload, not five.
 */

function isHttpUrl(url) {
  return typeof url === 'string' && /^https?:\/\//.test(url);
}

function originOf(url) {
  try { return new URL(url).origin; } catch { return null; }
}

/**
 * @param {Array<{id: number, url: string}>} tabs - raw chrome.tabs.query({}) result
 * @param {Set<string>} scannedOrigins - origins that already have a scan:<origin> entry in storage
 * @returns {{ httpTabCount: number, uniqueOrigins: string[], toReload: Array<{tabId: number, origin: string}> }}
 */
function selectTabsToReload(tabs, scannedOrigins) {
  const httpTabs = (tabs || []).filter(t => isHttpUrl(t.url));

  const originByTab = new Map();
  for (const t of httpTabs) {
    const origin = originOf(t.url);
    if (origin) originByTab.set(t.id, origin);
  }

  const uniqueOrigins = [...new Set(originByTab.values())];
  const toReload = [];
  const seen = new Set();
  for (const [tabId, origin] of originByTab) {
    if (scannedOrigins.has(origin)) continue;
    if (seen.has(origin)) continue;
    seen.add(origin);
    toReload.push({ tabId, origin });
  }

  return { httpTabCount: httpTabs.length, uniqueOrigins, toReload };
}

if (typeof module !== 'undefined') {
  module.exports = { selectTabsToReload, isHttpUrl, originOf };
}
