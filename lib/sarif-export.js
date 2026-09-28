/**
 * ISA — SARIF 2.1.0 export.
 *
 * SARIF (Static Analysis Results Interchange Format) is the OASIS standard
 * GitHub Code Scanning, GitLab, and Azure DevOps ingest natively for
 * automated security gates in CI pipelines — turning a manual popup click
 * into something a pipeline can fail a build on. Schema confirmed against
 * the current spec and several real emitters before writing this (GitHub's
 * own SARIF docs, the OASIS spec's minimal example, and existing
 * SARIF-emitting tools) rather than assumed from memory, since a malformed
 * SARIF file either fails to upload or silently doesn't produce alerts.
 *
 * One structural note worth being explicit about: SARIF's artifactLocation
 * was designed with source-code files in mind ("a file in the repository").
 * ISA isn't a static-code scanner — it's scanning a live web origin. The
 * honest mapping here is that the artifact IS the origin URL itself, and
 * every result's physicalLocation.artifactLocation.uri is set to that
 * origin, since there's no file/line-number equivalent for "this response
 * header is missing" or "this CVE-matched library is running here". A SARIF
 * *viewer* built for source code may render this a little unusually
 * (everything pointing at one "file"), but the document itself is valid
 * SARIF 2.1.0, and this is the same pattern other URL/API-focused security
 * scanners use — the alternative (inventing a fake file path) would be
 * less honest, not more compatible.
 *
 * Only converts things that are actual findings, not every raw detection —
 * a technology ISA detected with zero matched CVEs isn't a "result" any
 * more than a linter reporting every function it looked at and found
 * nothing wrong with. Included: matched CVEs (from vuln-db.json version-range
 * matching), exposure-check findings, and failing/weak security header
 * checks. Excluded: clean technology detections, passing header checks,
 * "info"-severity exposure findings (security.txt presence, sitemap
 * listing) — informational context, not a problem to flag in a CI gate.
 */

function severityToSarifLevel(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'medium') return 'warning';
  return 'note'; // low, info, or anything unrecognized — never silently dropped, just least-severe
}

function buildSarif({ origin, scannedAt, findings = [], exposureFindings = [], securityChecks = [] }) {
  const rules = new Map(); // ruleId -> rule object, de-duplicated across results
  const results = [];
  const artifactUri = origin || 'unknown-origin';

  function addRule(id, name, description, helpUri) {
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name,
        shortDescription: { text: description },
        ...(helpUri ? { helpUri } : {})
      });
    }
  }

  // CVE matches (already version-range-confirmed by matcher.js against vuln-db.json)
  for (const finding of findings) {
    for (const vuln of finding.vulnerabilities || []) {
      const ruleId = `isa-cve/${vuln.cve}`;
      addRule(ruleId, vuln.cve, `Known vulnerability in ${finding.name}`, `https://nvd.nist.gov/vuln/detail/${vuln.cve}`);
      results.push({
        ruleId,
        level: severityToSarifLevel(vuln.severity),
        message: { text: `${finding.name}${finding.version ? ` ${finding.version}` : ''}: ${vuln.summary} (${vuln.cve}, ${vuln.severity})` },
        locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri } } }],
        properties: { technology: finding.name, version: finding.version || null, cve: vuln.cve, severity: vuln.severity }
      });
    }
  }

  // Exposure-check findings, excluding pure-informational ones
  for (const f of exposureFindings) {
    if (f.severity === 'info') continue;
    const ruleId = `isa-exposure/${f.id.split(':')[0]}`;
    addRule(ruleId, f.title, 'Exposure check finding');
    results.push({
      ruleId,
      level: severityToSarifLevel(f.severity),
      message: { text: f.detail },
      locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri } } }],
      properties: { severity: f.severity, findingId: f.id }
    });
  }

  // Failing/weak security header checks
  for (const c of securityChecks) {
    // security-headers.js only ever emits 'present' | 'weak' | 'missing' —
    // NOT 'pass'/'ok'. This used to check for the wrong strings, which
    // meant a 'present' (passing) check was never excluded and leaked into
    // SARIF output as a spurious result. See tests/run.mjs for the
    // regression test using the real status vocabulary.
    if (c.status === 'present') continue;
    const ruleId = `isa-header/${c.header.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
    addRule(ruleId, c.header, `Security header check: ${c.header}`);
    results.push({
      ruleId,
      level: c.status === 'missing' ? 'warning' : 'note',
      message: { text: `${c.header}: ${c.detail}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri } } }],
      properties: { status: c.status }
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ISA',
          fullName: 'ISA — Integrated Stack Analyzer',
          informationUri: 'https://github.com/',
          rules: [...rules.values()]
        }
      },
      invocations: [{
        executionSuccessful: true,
        endTimeUtc: scannedAt || new Date().toISOString()
      }],
      results
    }]
  };
}

if (typeof module !== 'undefined') {
  module.exports = { buildSarif, severityToSarifLevel };
}
