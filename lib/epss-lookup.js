/**
 * ISA — EPSS (Exploit Prediction Scoring System) lookup.
 *
 * FIRST.org's EPSS gives a daily-updated probability (0-1) that a given
 * CVE will actually be exploited in the wild in the next 30 days, plus a
 * percentile rank against every other scored CVE. This is a different,
 * complementary signal from CISA KEV: KEV says "this CVE has definitely
 * been exploited already"; EPSS says "here is the statistical likelihood
 * this one will be, even if it hasn't (yet)". Together they let a
 * researcher triage a long list of version-matched CVEs by realistic
 * priority instead of by CVSS severity alone — a critical-severity CVE
 * with a low EPSS score may matter less right now than a medium-severity
 * one with a high score.
 *
 * Confirmed against the live, currently-published API response shape
 * before writing this: GET https://api.first.org/data/v1/epss?cve=<ids>
 * returns { status, data: [{ cve, epss, percentile, date }] }, where epss
 * and percentile are numeric strings in [0,1]. No API key, no auth. Opt-in
 * for the same reason as the NVD and KEV lookups — it is one of the few
 * places ISA talks to a server besides the target and (optionally) NVD/KEV.
 *
 * Batches CVE IDs into as few requests as possible (the API explicitly
 * supports a comma-separated cve list, capped at 2000 characters including
 * commas) rather than firing one request per CVE.
 */

const EPSS_ENDPOINT = 'https://api.first.org/data/v1/epss';
const MAX_QUERY_CHARS = 2000;

function batchCveIds(cveIds) {
  const batches = [];
  let current = [];
  let currentLen = 0;
  for (const id of cveIds) {
    const addedLen = current.length ? id.length + 1 : id.length; // +1 for the joining comma
    if (currentLen + addedLen > MAX_QUERY_CHARS && current.length) {
      batches.push(current);
      current = [];
      currentLen = 0;
    }
    current.push(id);
    currentLen += current.length === 1 ? id.length : id.length + 1;
  }
  if (current.length) batches.push(current);
  return batches;
}

function classifyRisk(epssScore) {
  if (epssScore >= 0.5) return 'high';
  if (epssScore >= 0.1) return 'elevated';
  return 'low';
}

async function fetchEpssBatch(cveIds, fetchImpl = fetch, timeoutMs = 6000) {
  const url = `${EPSS_ENDPOINT}?cve=${encodeURIComponent(cveIds.join(','))}`;
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchImpl(url, { signal: controller.signal });
    if (!resp.ok) return { ok: false, error: `EPSS API returned ${resp.status}` };
    const data = await resp.json();
    if (!Array.isArray(data.data)) return { ok: false, error: 'unexpected EPSS response shape (no data array)' };
    return {
      ok: true,
      results: data.data.map(d => ({
        cve: d.cve,
        epss: parseFloat(d.epss),
        percentile: parseFloat(d.percentile),
        date: d.date,
        risk: classifyRisk(parseFloat(d.epss))
      }))
    };
  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, error: 'EPSS request timed out' };
    return { ok: false, error: err.message || 'network error' };
  } finally {
    clearTimeout(t);
  }
}

async function queryEpssScores(cveIds, fetchImpl = fetch, timeoutMs = 6000) {
  const unique = [...new Set((cveIds || []).filter(Boolean))];
  if (unique.length === 0) return { ok: true, results: [] };

  const batches = batchCveIds(unique);
  const allResults = [];
  for (const batch of batches) {
    const res = await fetchEpssBatch(batch, fetchImpl, timeoutMs);
    if (!res.ok) return res; // surface the first failure rather than silently partial-returning
    allResults.push(...res.results);
  }
  return { ok: true, results: allResults };
}

if (typeof module !== 'undefined') {
  module.exports = { queryEpssScores, fetchEpssBatch, batchCveIds, classifyRisk, EPSS_ENDPOINT };
}
