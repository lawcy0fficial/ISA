/**
 * ISA — CPE-based exact NVD matching.
 *
 * live-cve-lookup.js's own comments have long documented the gap this
 * fills: NVD's keywordSearch is fuzzy free-text matching, so a query for
 * "Bootstrap 3.4.1" can surface an unrelated firmware advisory that
 * happens to mention the word "Bootstrap". NVD's API also supports exact
 * CPE-based matching (`virtualMatchString` + `versionStart`/`versionEnd`),
 * which is precise instead of fuzzy — but implementing it needs the exact
 * vendor:product CPE identifier for each technology, which cannot be
 * guessed (an official NVD product page exists per real CPE; getting the
 * vendor/product string wrong silently queries the wrong software).
 *
 * TECH_TO_CPE below is deliberately small: every entry was checked
 * against NVD's own official CPE dictionary product pages (nvd.nist.gov/
 * products/cpe/detail/...) before being added — not guessed from the
 * technology's display name. "getbootstrap:bootstrap", not "twitter:
 * bootstrap" or "bootstrap:bootstrap" — the actual vendor NVD uses is
 * sometimes surprising, which is exactly why this table has to be
 * curated rather than derived.
 *
 * HONESTY NOTE, because everything else added this session was tested
 * end-to-end against a real or mocked live response, and this one thing
 * genuinely wasn't: the parameter *names*, *semantics*, and the exact
 * jQuery/jQuery-UI/Bootstrap/Lodash/Moment.js CPE strings below are
 * confirmed against NVD's own official developer documentation and
 * product pages — high confidence, not guessed. What I could NOT confirm
 * is the live, end-to-end parameterized query response, because the only
 * fetch tool available in this environment appears to normalize/cache
 * NVD query URLs down to their base path, silently dropping the query
 * string (confirmed by requesting a jQuery-UI-scoped query and receiving
 * the entire 250,000+ record unfiltered database back instead). That is
 * a limitation of this development environment's tooling, not evidence
 * against the feature — a real browser extension's fetch() is not
 * subject to it. But unlike every other module added this session, this
 * one has NOT been personally verified against a real parameterized live
 * response, and that gap is real: if NVD ever changes virtualMatchString
 * behavior, this would be the one place ISA wouldn't have caught it
 * before shipping. Treat this as v1/experimental until it's been run
 * against the real API from an actual loaded extension.
 */

const NVD_CPE_QUERY_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// vendor:product only — version is supplied separately per-query via
// versionStart/versionEnd, never baked into this table.
const TECH_TO_CPE = {
  'jQuery': { vendor: 'jquery', product: 'jquery' },
  'jQuery UI': { vendor: 'jqueryui', product: 'jquery_ui' },
  'Bootstrap': { vendor: 'getbootstrap', product: 'bootstrap' },
  'Lodash': { vendor: 'lodash', product: 'lodash' },
  'Moment.js': { vendor: 'momentjs', product: 'moment' },
  'WordPress': { vendor: 'wordpress', product: 'wordpress' }
};

function buildCpeQueryUrl(techName, version) {
  const cpe = TECH_TO_CPE[techName];
  if (!cpe || !version) return null;
  const virtualMatchString = `cpe:2.3:a:${cpe.vendor}:${cpe.product}`;
  const params = new URLSearchParams({
    virtualMatchString,
    versionStart: version,
    versionStartType: 'including',
    versionEnd: version,
    versionEndType: 'including'
  });
  return `${NVD_CPE_QUERY_ENDPOINT}?${params.toString()}`;
}

function extractCvssFromCpeResult(cveEntry) {
  const metrics = cveEntry.metrics || {};
  const order = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const key of order) {
    const arr = metrics[key];
    if (arr && arr.length) {
      const data = arr[0].cvssData || {};
      return { score: data.baseScore ?? null, severity: data.baseSeverity || arr[0].baseSeverity || null };
    }
  }
  return { score: null, severity: null };
}

async function queryCpeMatch(techName, version, fetchImpl = fetch, timeoutMs = 8000) {
  const url = buildCpeQueryUrl(techName, version);
  if (!url) return { ok: true, skipped: true, results: [] }; // no CPE mapping or no version — not an error

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchImpl(url, { signal: controller.signal });
    if (!resp.ok) return { ok: false, error: `NVD API returned ${resp.status}` };
    const data = await resp.json();
    if (!Array.isArray(data.vulnerabilities)) return { ok: true, skipped: false, results: [] };
    return {
      ok: true,
      skipped: false,
      results: data.vulnerabilities.map(v => {
        const cve = v.cve;
        const { score, severity } = extractCvssFromCpeResult(cve);
        const desc = (cve.descriptions || []).find(d => d.lang === 'en');
        return { id: cve.id, description: desc ? desc.value : null, score, severity };
      })
    };
  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, error: 'NVD CPE request timed out' };
    return { ok: false, error: err.message || 'network error' };
  } finally {
    clearTimeout(t);
  }
}

if (typeof module !== 'undefined') {
  module.exports = { queryCpeMatch, buildCpeQueryUrl, TECH_TO_CPE, NVD_CPE_QUERY_ENDPOINT, extractCvssFromCpeResult };
}
