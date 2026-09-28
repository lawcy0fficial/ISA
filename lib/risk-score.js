/**
 * ISA — unified risk score.
 *
 * Everything else in ISA reports one dimension at a time: a header grade,
 * a list of exposure findings, a per-technology CVE count. None of those
 * alone answers the actual triage question — "how bad is this origin,
 * overall, right now" — without mentally averaging four panels together.
 * This is a pure combining function, not a new data source: it takes the
 * outputs ISA already computed (security-headers.js's grade, the exposure
 * findings array, the vuln-db matches already attached to each finding)
 * and reduces them to one 0-100 score and letter grade, with a visible
 * breakdown of what contributed — never a black-box number.
 *
 * Weighting rationale, stated plainly since a scoring formula is a set of
 * value judgments and hiding that would just make it look more objective
 * than it is:
 *   - Header grade is the largest single input (40%) because it reflects
 *     the site's actual security posture across many independent controls
 *     at once, not a single point-in-time finding.
 *   - Confirmed CVEs (matched via version range) count more than exposure
 *     findings, because a CVE is a specific, named, already-cataloged
 *     issue; an exposure finding is often informational (security.txt,
 *     sitemap disclosure) rather than a vulnerability.
 *   - A CVE confirmed in CISA's KEV catalog is weighted far above an
 *     unconfirmed one — that's the entire point of the KEV integration:
 *     confirmed active exploitation is categorically more urgent than a
 *     theoretical version match.
 *   - "info" severity exposure findings (security.txt present/absent,
 *     sitemap listing) contribute zero — they're attack-surface context,
 *     not a risk signal.
 */

const EXPOSURE_SEVERITY_WEIGHT = { critical: 20, medium: 10, low: 4, info: 0 };
const CVE_SEVERITY_WEIGHT = { critical: 15, high: 10, medium: 5, low: 2 };
const KEV_CONFIRMED_BONUS = 25; // per CVE confirmed in CISA KEV, on top of its severity weight

function scoreFromHeaderGrade(grade) {
  // A-F maps onto a 0-100 contribution before the 40% weighting is applied
  const map = { A: 100, B: 80, C: 60, D: 40, F: 15 };
  return map[grade] ?? 50; // unknown/ungraded input treated as a neutral midpoint, not zero
}

function letterFromScore(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 55) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

/**
 * @param {object} params
 * @param {{grade: string}|null} params.security - security-headers.js gradeHeaders() output, or null if not yet checked
 * @param {Array<{severity: string}>} params.exposureFindings - exposure-checks.js findings, or []
 * @param {Array<{vulnerabilities: Array<{cve: string, severity: string}>}>} params.techFindings - matcher.js evaluate() findings
 * @param {string[]} params.kevConfirmedCveIds - CVE ID strings the user has explicitly confirmed via CISA KEV (opt-in — see kev-lookup.js). Empty if never checked; this never runs itself, it only reflects what the user already confirmed.
 */
function computeRiskScore({ security, exposureFindings = [], techFindings = [], kevConfirmedCveIds = [] }) {
  const kevSet = new Set((kevConfirmedCveIds || []).map(id => id.toUpperCase()));
  const breakdown = [];

  // Header grade component (40% weight)
  const headerScore = security ? scoreFromHeaderGrade(security.grade) : null;
  const headerDeduction = headerScore !== null ? (100 - headerScore) * 0.4 : 0;
  if (headerScore !== null) {
    breakdown.push({ label: `Security headers (grade ${security.grade})`, deduction: headerDeduction });
  }

  // CVE component: penalty accumulates from matched CVEs, weighted by
  // severity, with a further bonus for anything the user has confirmed in
  // CISA KEV during this session.
  let cvePenalty = 0;
  let cveCount = 0;
  let kevCount = 0;
  for (const finding of techFindings) {
    for (const vuln of finding.vulnerabilities || []) {
      cveCount++;
      const isKev = kevSet.has((vuln.cve || '').toUpperCase());
      cvePenalty += CVE_SEVERITY_WEIGHT[vuln.severity] || 5;
      if (isKev) { cvePenalty += KEV_CONFIRMED_BONUS; kevCount++; }
    }
  }
  if (cveCount > 0) {
    breakdown.push({
      label: `${cveCount} matched CVE${cveCount === 1 ? '' : 's'}${kevCount ? ` (${kevCount} confirmed actively exploited)` : ''}`,
      deduction: cvePenalty
    });
  }

  // Exposure component
  let exposurePenalty = 0;
  const exposureCounts = {};
  for (const f of exposureFindings) {
    const w = EXPOSURE_SEVERITY_WEIGHT[f.severity] ?? 0;
    exposurePenalty += w;
    if (w > 0) exposureCounts[f.severity] = (exposureCounts[f.severity] || 0) + 1;
  }
  const exposureSummary = Object.entries(exposureCounts).map(([sev, n]) => `${n} ${sev}`).join(', ');
  if (exposurePenalty > 0) {
    breakdown.push({ label: `Exposure findings (${exposureSummary})`, deduction: exposurePenalty });
  }

  const totalDeduction = headerDeduction + cvePenalty + exposurePenalty;
  const score = Math.max(0, Math.min(100, Math.round(100 - totalDeduction)));

  return {
    score,
    grade: letterFromScore(score),
    breakdown,
    hasData: security !== null || techFindings.some(f => (f.vulnerabilities || []).length > 0) || exposureFindings.length > 0
  };
}

if (typeof module !== 'undefined') {
  module.exports = { computeRiskScore, scoreFromHeaderGrade, letterFromScore };
}
