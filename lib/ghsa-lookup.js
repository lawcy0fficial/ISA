/**
 * ISA — GitHub Security Advisories (GHSA) lookup.
 *
 * A third, complementary correlation source alongside NVD (live-cve-lookup.js),
 * CISA KEV (kev-lookup.js), and FIRST EPSS (epss-lookup.js). The reason it
 * earns its own module rather than being folded into the NVD one: GHSA's
 * database is maintained by GitHub specifically for open-source package
 * ecosystems (npm, pip, RubyGems, etc.) and is often faster to publish a
 * given npm-ecosystem advisory than NVD — sometimes NVD never gets a clean
 * CPE match for a small JS library at all, which is exactly the category
 * most of ISA's ruleset falls into. Where NVD lookup answers "what does
 * the government's database say about this CVE", this answers "what does
 * the actual npm/pip package ecosystem's own advisory database say" —
 * different curators, occasionally different coverage, both worth having.
 *
 * Confirmed against the live, currently-published API response shape
 * before writing this: GET https://api.github.com/advisories?cve_id=<id>
 * returns a JSON array of advisory objects with `ghsa_id`, `cve_id`,
 * `summary`, `severity`, `html_url`, and a `vulnerabilities[]` array with
 * per-package `ecosystem`, `vulnerable_version_range`, and
 * `first_patched_version`. No API key required for public data. GitHub's
 * unauthenticated rate limit is 60 requests/hour per IP — low enough that
 * this batches by making one request per unique CVE ID (there is no
 * documented multi-CVE batch parameter, unlike EPSS) but is opt-in, same
 * as the other three lookups, so it's only ever spent on CVEs the user
 * actually asked to confirm.
 */

const GHSA_ENDPOINT = 'https://api.github.com/advisories';

async function fetchGhsaForCve(cveId, fetchImpl = fetch, timeoutMs = 6000) {
  const url = `${GHSA_ENDPOINT}?cve_id=${encodeURIComponent(cveId)}`;
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchImpl(url, {
      signal: controller.signal,
      headers: { Accept: 'application/vnd.github+json' }
    });
    if (resp.status === 403 || resp.status === 429) {
      return { ok: false, error: 'GitHub API rate limit reached (60 requests/hour unauthenticated) — try again later' };
    }
    if (!resp.ok) return { ok: false, error: `GitHub advisories API returned ${resp.status}` };
    const data = await resp.json();
    if (!Array.isArray(data)) return { ok: false, error: 'unexpected GHSA response shape (not an array)' };
    return {
      ok: true,
      advisories: data.map(a => ({
        ghsaId: a.ghsa_id,
        cveId: a.cve_id,
        summary: a.summary || null,
        severity: a.severity || null,
        htmlUrl: a.html_url || null,
        publishedAt: a.published_at || null,
        packages: (a.vulnerabilities || []).map(v => ({
          ecosystem: v.package && v.package.ecosystem,
          name: v.package && v.package.name,
          vulnerableRange: v.vulnerable_version_range || null,
          firstPatched: v.first_patched_version || null
        }))
      }))
    };
  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, error: 'GitHub advisories request timed out' };
    return { ok: false, error: err.message || 'network error' };
  } finally {
    clearTimeout(t);
  }
}

// Looks up several CVE IDs, one request each (see module doc for why no
// batch endpoint exists here unlike EPSS). Stops and surfaces the first
// error rather than silently returning a partial result, same convention
// as epss-lookup.js's queryEpssScores.
async function queryGhsaAdvisories(cveIds, fetchImpl = fetch, timeoutMs = 6000) {
  const unique = [...new Set((cveIds || []).filter(Boolean))];
  if (unique.length === 0) return { ok: true, results: [] };

  const results = [];
  for (const id of unique) {
    const res = await fetchGhsaForCve(id, fetchImpl, timeoutMs);
    if (!res.ok) return res;
    if (res.advisories.length > 0) results.push({ cve: id, advisories: res.advisories });
  }
  return { ok: true, results };
}

if (typeof module !== 'undefined') {
  module.exports = { queryGhsaAdvisories, fetchGhsaForCve, GHSA_ENDPOINT };
}
