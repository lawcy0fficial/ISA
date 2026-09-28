/**
 * ISA — CISA Known Exploited Vulnerabilities (KEV) cross-reference.
 *
 * This is the actual "confirming exploits" feature, done the only way that
 * fits ISA's own rules: not by running an exploit, but by cross-referencing
 * a CVE ID that ISA already found (via the local vuln-db.json version-range
 * match, or the live NVD lookup) against CISA's public KEV catalog — the
 * US government's authoritative, continuously-updated list of CVEs that are
 * confirmed to be actively exploited in the wild right now. A hit here is a
 * categorically stronger signal than "this version has a known CVE": it
 * means real-world attackers are already using it, which is exactly the
 * kind of prioritization signal that separates a security tool a
 * researcher can trust from one that just dumps every theoretical CVE.
 *
 * Like the NVD lookup, this sends data to a server other than the target
 * being scanned (cisa.gov), so it is opt-in — never run automatically —
 * and it only ever sends CVE ID strings ISA has already found, nothing
 * about the page, the user, or the target site.
 *
 * Design note on why this fetches the WHOLE catalog rather than querying
 * per-CVE: the feed has no server-side filter-by-CVE-ID parameter (it is a
 * flat JSON dump, confirmed against the live, currently-published schema —
 * see the field names below), so the only way to check membership is to
 * fetch the catalog and look CVE IDs up locally. That is also exactly how
 * every other public consumer of this feed works. The catalog is fetched
 * once per popup session and reused for every CVE checked in that session,
 * not re-fetched per CVE.
 */

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

async function fetchKevCatalog(fetchImpl = fetch, timeoutMs = 8000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchImpl(KEV_URL, { signal: controller.signal });
    if (!resp.ok) return { ok: false, error: `CISA KEV feed returned ${resp.status}` };
    const data = await resp.json();
    if (!Array.isArray(data.vulnerabilities)) {
      return { ok: false, error: 'unexpected KEV feed shape (no vulnerabilities array)' };
    }
    return { ok: true, catalogVersion: data.catalogVersion || null, count: data.vulnerabilities.length, vulnerabilities: data.vulnerabilities };
  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, error: 'CISA KEV request timed out' };
    return { ok: false, error: err.message || 'network error' };
  } finally {
    clearTimeout(t);
  }
}

// Pure, offline-testable: given a fetched catalog and a list of CVE IDs
// ISA already found elsewhere, return only the ones present in KEV, with
// the fields that matter for triage. Case-insensitive on the CVE ID since
// "cve" is occasionally typed lowercase by callers even though CISA's own
// data is always uppercase.
function crossReferenceKev(cveIds, catalog) {
  if (!catalog || !Array.isArray(catalog.vulnerabilities)) return [];
  const wanted = new Set((cveIds || []).map(id => String(id).toUpperCase()));
  if (wanted.size === 0) return [];
  return catalog.vulnerabilities
    .filter(v => wanted.has(String(v.cveID || '').toUpperCase()))
    .map(v => ({
      cve: v.cveID,
      vulnerabilityName: v.vulnerabilityName || null,
      vendorProject: v.vendorProject || null,
      product: v.product || null,
      dateAdded: v.dateAdded || null,
      dueDate: v.dueDate || null,
      knownRansomwareCampaignUse: v.knownRansomwareCampaignUse || 'Unknown',
      shortDescription: v.shortDescription || null
    }));
}

if (typeof module !== 'undefined') {
  module.exports = { fetchKevCatalog, crossReferenceKev, KEV_URL };
}
