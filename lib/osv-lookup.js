/**
 * ISA — OSV.dev lookup.
 *
 * Structurally different from kev-lookup.js/epss-lookup.js/ghsa-lookup.js:
 * those three all take CVE ID strings ISA already found (via the local
 * vuln-db.json version-range match) and ask "is this specific CVE
 * confirmed exploited / how likely / does GHSA also know about it".
 *
 * OSV works the other way around: given a package name, ecosystem, and
 * version — which ISA already has for any detected, versioned technology,
 * whether or not vuln-db.json has an entry for it — it returns whatever
 * vulnerabilities OSV knows about for that exact version, aggregated from
 * GHSA, PyPA, RustSec, and dozens of other OSV-format sources. This means
 * OSV can surface a real vulnerability for a technology ISA detects but
 * has no local vuln-db.json entry for at all — the 12-entry local table
 * only covers what's been manually curated and verified so far, but OSV
 * covers whatever the wider open-source vulnerability-database ecosystem
 * already aggregated, for anything ISA can map to a package name.
 *
 * That package-name mapping is the real constraint: ISA's ruleset names
 * technologies the way a researcher would recognize them ("jQuery UI",
 * "React"), not necessarily the way they're published to a package
 * registry. TECH_TO_PACKAGE below is deliberately small and only contains
 * mappings verified against the actual published package name — an wrong
 * mapping here would silently query the wrong package and either miss
 * real vulnerabilities or (worse) return a different package's
 * vulnerabilities mislabeled as this technology's. A technology absent
 * from this table is simply skipped, never guessed.
 *
 * Schema and endpoint confirmed against the live, currently-published OSV
 * API docs before writing this: POST https://api.osv.dev/v1/query with
 * {"package": {"name", "ecosystem"}, "version"} returns
 * {"vulns": [{id, summary, aliases: [...], severity, affected, ...}]}.
 * No API key, and OSV.dev's own FAQ states the API is not currently rate
 * limited. `aliases` is where CVE IDs show up for OSV records sourced
 * from GHSA/NVD-linked advisories — an OSV record doesn't always have a
 * CVE alias (some ecosystems, like RustSec, mint their own IDs with no
 * CVE assigned at all), so `cveAliases` below can legitimately be empty
 * for a real, valid finding.
 */

// Only entries verified against the actual published package name on its
// registry — never guessed from the technology's display name.
const TECH_TO_PACKAGE = {
  'jQuery': { name: 'jquery', ecosystem: 'npm' },
  'jQuery UI': { name: 'jquery-ui', ecosystem: 'npm' },
  'React': { name: 'react', ecosystem: 'npm' },
  'Vue.js': { name: 'vue', ecosystem: 'npm' },
  'Angular': { name: '@angular/core', ecosystem: 'npm' },
  'Lodash': { name: 'lodash', ecosystem: 'npm' },
  'Moment.js': { name: 'moment', ecosystem: 'npm' },
  'Bootstrap': { name: 'bootstrap', ecosystem: 'npm' },
  'Axios': { name: 'axios', ecosystem: 'npm' },
  'Express': { name: 'express', ecosystem: 'npm' },
  'D3.js': { name: 'd3', ecosystem: 'npm' },
  'Chart.js': { name: 'chart.js', ecosystem: 'npm' },
  'TinyMCE': { name: 'tinymce', ecosystem: 'npm' },
  'CKEditor': { name: 'ckeditor4', ecosystem: 'npm' },
  'Swiper': { name: 'swiper', ecosystem: 'npm' },
  'Socket.IO': { name: 'socket.io', ecosystem: 'npm' },
  'Highcharts': { name: 'highcharts', ecosystem: 'npm' },
  'Leaflet': { name: 'leaflet', ecosystem: 'npm' },
  'Next.js': { name: 'next', ecosystem: 'npm' },
  'Nuxt.js': { name: 'nuxt', ecosystem: 'npm' },
  'SvelteKit': { name: '@sveltejs/kit', ecosystem: 'npm' },
  'Astro': { name: 'astro', ecosystem: 'npm' },
  'Gatsby': { name: 'gatsby', ecosystem: 'npm' },
  'Remix': { name: '@remix-run/react', ecosystem: 'npm' },
  'Vite': { name: 'vite', ecosystem: 'npm' },
  'Webpack': { name: 'webpack', ecosystem: 'npm' },
  'WordPress': { name: 'wordpress', ecosystem: 'WordPress' }
};

function lookupPackageMapping(techName) {
  return TECH_TO_PACKAGE[techName] || null;
}

async function queryOsv(pkg, version, fetchImpl = fetch, timeoutMs = 6000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: pkg.name, ecosystem: pkg.ecosystem }, version }),
      signal: controller.signal
    });
    if (!resp.ok) return { ok: false, error: `OSV API returned ${resp.status}` };
    const data = await resp.json();
    if (!Array.isArray(data.vulns)) return { ok: true, vulns: [] }; // no vulns field = clean result, not an error
    return {
      ok: true,
      vulns: data.vulns.map(v => ({
        id: v.id,
        summary: v.summary || null,
        cveAliases: (v.aliases || []).filter(a => /^CVE-\d{4}-\d+$/.test(a)),
        severity: (v.severity && v.severity[0] && v.severity[0].score) || null,
        published: v.published || null,
        references: (v.references || []).map(r => r.url).filter(Boolean).slice(0, 5)
      }))
    };
  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, error: 'OSV request timed out' };
    return { ok: false, error: err.message || 'network error' };
  } finally {
    clearTimeout(t);
  }
}

// Looks up OSV vulnerabilities for a detected+versioned finding, skipping
// (not erroring on) any technology absent from TECH_TO_PACKAGE — that's
// an expected, common case, not a failure.
async function queryOsvForFinding(techName, version, fetchImpl = fetch, timeoutMs = 6000) {
  const pkg = lookupPackageMapping(techName);
  if (!pkg) return { ok: true, skipped: true, vulns: [] };
  if (!version) return { ok: true, skipped: true, vulns: [] };
  const result = await queryOsv(pkg, version, fetchImpl, timeoutMs);
  return result.ok ? { ...result, skipped: false, package: pkg } : result;
}

if (typeof module !== 'undefined') {
  module.exports = { queryOsv, queryOsvForFinding, lookupPackageMapping, TECH_TO_PACKAGE };
}
