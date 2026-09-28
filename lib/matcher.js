/**
 * ISA — Integrated Stack Analyzer
 * Core matching engine.
 *
 * Every finding is derived from concrete evidence (a matched header, cookie,
 * script path, DOM attribute, or a live global object value). Nothing is
 * inferred from a single weak signal alone — confidence is the sum of every
 * signal that actually matched, capped at 100, and every match keeps a
 * pointer back to the raw text that triggered it so a researcher can verify
 * by hand.
 */

// ---- version range comparator for vuln-db.json -----------------------

function parseVersion(v) {
  return String(v).split('.').map(n => parseInt(n, 10) || 0);
}

function compareVersions(a, b) {
  const pa = parseVersion(a), pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x - y;
  }
  return 0;
}

// Supports: "<x.y.z", "<=x.y.z", ">=x.y.z <a.b.c", ">x.y.z"
function versionInRange(version, range) {
  if (!version) return false;
  const clauses = range.trim().split(/\s+/);
  return clauses.every(clause => {
    const m = clause.match(/^(<=|>=|<|>)([0-9.]+)$/);
    if (!m) return false;
    const [, op, bound] = m;
    const cmp = compareVersions(version, bound);
    switch (op) {
      case '<': return cmp < 0;
      case '<=': return cmp <= 0;
      case '>': return cmp > 0;
      case '>=': return cmp >= 0;
      default: return false;
    }
  });
}

// ---- version-conflict detection ------------------------------------

// Two captured version strings "conflict" only if they genuinely disagree —
// not just differ in precision. "6.4" from one signal and "6.4.2" from
// another aren't a conflict (one is just less specific); "1.12.4" and
// "3.6.0" are a real conflict worth surfacing rather than silently
// resolving by picking whichever signal had higher confidence.
function versionsConflict(a, b) {
  if (!a || !b || a === b) return false;
  const segA = String(a).replace(/^v/i, '').split('.');
  const segB = String(b).replace(/^v/i, '').split('.');
  const len = Math.min(segA.length, segB.length);
  for (let i = 0; i < len; i++) {
    if (segA[i] !== segB[i]) return true;
  }
  return false; // one is a prefix of the other — same version, different precision
}

function dedupeByCve(vulns) {
  const seen = new Set();
  return vulns.filter(v => {
    if (seen.has(v.cve)) return false;
    seen.add(v.cve);
    return true;
  });
}

function findVulnerabilities(techName, version, vulnDb) {
  if (!version) return [];
  return (vulnDb.entries || [])
    .filter(e => e.tech === techName && versionInRange(version, e.range))
    .map(e => ({ cve: e.cve, severity: e.severity, summary: e.summary, range: e.range }));
}

// ---- signal evaluators --------------------------------------------------
// Each returns either null (no match) or { matched: string, version?: string, confidence }

function evalRegexSignal(rule, subject) {
  if (subject == null) return null;
  let re;
  try {
    re = new RegExp(rule.regex, 'i');
  } catch {
    // a malformed regex (most likely from a hand-typed custom rule) must
    // never take down matching for every other technology in the same
    // scan — isolate the failure to just this one signal.
    return null;
  }
  const m = re.exec(subject);
  if (!m) return null;
  const version = rule.version ? m[rule.version] : undefined;
  return { matched: m[0].slice(0, 180), version, confidence: rule.confidence };
}

function evalHeaderSignals(rules, headers) {
  const out = [];
  for (const rule of rules || []) {
    const val = headers[rule.key.toLowerCase()];
    const r = evalRegexSignal(rule, val);
    if (r) out.push({ signal: `header:${rule.key}`, ...r });
  }
  return out;
}

function evalCookieSignals(rules, cookieNames) {
  const out = [];
  for (const rule of rules || []) {
    for (const name of cookieNames) {
      const r = evalRegexSignal(rule, name);
      if (r) { out.push({ signal: `cookie:${name}`, ...r }); break; }
    }
  }
  return out;
}

function evalMetaSignals(rules, metaTags) {
  const out = [];
  for (const rule of rules || []) {
    const tag = metaTags.find(m => m.name && m.name.toLowerCase() === rule.name.toLowerCase());
    if (!tag) continue;
    const r = evalRegexSignal(rule, tag.content);
    if (r) out.push({ signal: `meta:${rule.name}`, ...r });
  }
  return out;
}

function evalScriptSrcSignals(rules, scriptSrcs) {
  const out = [];
  for (const rule of rules || []) {
    for (const src of scriptSrcs) {
      const r = evalRegexSignal(rule, src);
      if (r) { out.push({ signal: 'scriptSrc', ...r }); break; }
    }
  }
  return out;
}

function evalRequestUrlSignals(rules, requestUrls) {
  const out = [];
  for (const rule of rules || []) {
    for (const url of requestUrls) {
      const r = evalRegexSignal(rule, url);
      if (r) { out.push({ signal: 'requestUrl', ...r }); break; }
    }
  }
  return out;
}

function evalCssVarSignals(rules, cssVars) {
  const out = [];
  for (const rule of rules || []) {
    for (const prop of cssVars) {
      const r = evalRegexSignal(rule, prop);
      if (r) { out.push({ signal: 'cssVar', ...r }); break; }
    }
  }
  return out;
}

function evalCspDomainSignals(rules, cspDomains) {
  // Deliberately a distinct signal type from requestUrl/scriptSrc, not
  // blended into them: a domain merely allowlisted in Content-Security-Policy
  // is weaker evidence than a domain actually observed in a real request or
  // script tag — the service might be configured but unused, or leftover
  // from a past integration. Kept honestly labeled and confidence-weighted
  // lower in the ruleset so the evidence log never implies more certainty
  // than a CSP allowlist entry actually provides.
  const out = [];
  for (const rule of rules || []) {
    for (const domain of cspDomains) {
      const r = evalRegexSignal(rule, domain);
      if (r) { out.push({ signal: 'cspDomain', ...r }); break; }
    }
  }
  return out;
}

function evalHtmlSignals(rules, htmlSample) {
  const out = [];
  for (const rule of rules || []) {
    const r = evalRegexSignal(rule, htmlSample);
    if (r) out.push({ signal: 'html', ...r });
  }
  return out;
}

function evalGlobalSignals(rules, globals) {
  const out = [];
  for (const rule of rules || []) {
    // background.js's probeGlobals() stores results under flat, literal
    // dotted-string keys (e.g. globals["jQuery.fn.jquery"]) rather than a
    // nested object, so lookup here must match by exact key, not by
    // traversing rule.path segment-by-segment.
    const val = globals[rule.path];
    if (val === undefined) continue;
    const strVal = typeof val === 'string' || typeof val === 'number' ? String(val) : 'present';
    out.push({
      signal: `global:${rule.path}`,
      matched: strVal.slice(0, 100),
      version: rule.isVersionLike ? strVal : undefined,
      confidence: rule.confidence
    });
  }
  return out;
}

function evalDomSignals(rules, domSample) {
  const out = [];
  for (const rule of rules || []) {
    if (rule.attrRegex) {
      const found = (domSample.attrs || []).find(a => a.attr === rule.attrRegex.attr);
      if (found) {
        let re;
        try {
          re = new RegExp(rule.attrRegex.regex, 'i');
        } catch {
          continue; // malformed regex — skip this signal, don't crash the scan
        }
        const m = re.exec(found.value);
        if (m) out.push({ signal: `dom-attr:${rule.attrRegex.attr}`, matched: found.value.slice(0, 100), version: rule.version ? m[rule.version] : undefined, confidence: rule.confidence });
      }
    } else if (rule.selector && (domSample.matchedSelectors || []).includes(rule.selector)) {
      out.push({ signal: `dom:${rule.selector}`, matched: rule.selector, confidence: rule.confidence });
    }
  }
  return out;
}

function evalFaviconSignal(faviconHash, faviconDb) {
  if (!faviconHash || !faviconDb || !faviconDb.hashes) return null;
  const entry = faviconDb.hashes[faviconHash];
  if (!entry) return null;
  return {
    signal: 'faviconHash',
    matched: faviconHash.slice(0, 16) + '…',
    version: undefined,
    confidence: entry.confidence || 50,
    techName: entry.tech
  };
}

// ---- main evaluation ----------------------------------------------------

/**
 * evidence shape:
 * {
 *   headers: { [lowercaseKey]: value },
 *   cookies: [names...],
 *   metaTags: [{name, content}],
 *   scriptSrcs: [urls...],
 *   requestUrls: [urls...] (XHR/fetch/WebSocket endpoints observed for this page load),
 *   cssVars: [customPropertyNames...] (e.g. "--bs-primary", "--chakra-colors-blue-500"),
 *   cspDomains: [domains...] (extracted from a Content-Security-Policy header's directives, e.g. "js.stripe.com"),
 *   htmlSample: string (truncated page HTML / inline script concat),
 *   globals: { ...probed window values },
 *   dom: { matchedSelectors: [...], attrs: [{attr, value}] },
 *   faviconHash: string | null
 * }
 */
function evaluate(evidence, ruleset, vulnDb, faviconDb) {
  const findings = [];

  for (const tech of ruleset.technologies) {
    let matches;
    try {
      const s = tech.signals || {};
      matches = [
        ...evalHeaderSignals(s.headers, evidence.headers || {}),
        ...evalCookieSignals(s.cookies, evidence.cookies || []),
        ...evalMetaSignals(s.meta, evidence.metaTags || []),
        ...evalScriptSrcSignals(s.scriptSrc, evidence.scriptSrcs || []),
        ...evalRequestUrlSignals(s.requestUrl, evidence.requestUrls || []),
      ...evalCssVarSignals(s.cssVars, evidence.cssVars || []),
      ...evalCspDomainSignals(s.cspDomains, evidence.cspDomains || []),
        ...evalHtmlSignals(s.html, evidence.htmlSample || ''),
        ...evalGlobalSignals(s.globals, evidence.globals || {}),
        ...evalDomSignals(s.dom, evidence.dom || {})
      ];
    } catch {
      // one broken rule (almost always a hand-typed custom rule with some
      // unforeseen shape issue) must never take down evaluation of every
      // other technology in the same scan.
      continue;
    }

    if (matches.length === 0) continue;

    const confidence = Math.min(100, matches.reduce((sum, m) => sum + m.confidence, 0));
    const versioned = matches.filter(m => m.version).sort((a, b) => b.confidence - a.confidence);
    const version = versioned.length ? versioned[0].version : null;

    // surface disagreement rather than silently discarding it: if two
    // signals genuinely disagree on version (not just differ in
    // precision), that's informative — a stale CDN-cached script name vs.
    // a live JS global reflecting what's actually deployed, for instance
    // — and hiding it behind "we picked the highest-confidence one" would
    // understate real uncertainty.
    const distinctVersions = [...new Set(versioned.map(m => m.version))];
    const versionConflict = distinctVersions.some((v, i) =>
      distinctVersions.slice(i + 1).some(other => versionsConflict(v, other))
    );

    findings.push({
      name: tech.name,
      categories: tech.categories,
      website: tech.website || null,
      verified: !!tech.verified,
      custom: !!tech.custom,
      implies: tech.implies || [],
      version,
      versionConflict,
      allVersionsFound: versionConflict ? distinctVersions : undefined,
      confidence,
      evidence: matches,
      vulnerabilities: versionConflict
        // when signals disagree, checking only the "winning" version could
        // silently miss a CVE that applies to whichever version turns out
        // to actually be correct — safer to check every distinct version
        // found and merge, deduped by CVE id, than to bet on one.
        ? dedupeByCve(distinctVersions.flatMap(v => findVulnerabilities(tech.name, v, vulnDb)))
        : (version ? findVulnerabilities(tech.name, version, vulnDb) : [])
    });
  }

  // pull in implied technologies not otherwise directly detected, at reduced confidence
  const byName = new Map(findings.map(f => [f.name, f]));
  // Multiple directly-detected technologies can imply the same target (PHP
  // is implied by 8 different entries in this ruleset alone) — the implied
  // confidence must come from whichever implicator has the HIGHEST
  // confidence, not just whichever happens to appear first in array order.
  // A weak, niche detection and a near-certain one implying the same thing
  // are not equally strong evidence for it.
  const impliedCandidates = new Map(); // targetName -> strongest implying finding
  for (const f of findings) {
    for (const impliedName of f.implies) {
      if (byName.has(impliedName)) continue; // already directly detected — never overridden by an inference
      const current = impliedCandidates.get(impliedName);
      if (!current || f.confidence > current.confidence) {
        impliedCandidates.set(impliedName, f);
      }
    }
  }
  for (const [impliedName, f] of impliedCandidates) {
    const impliedTech = ruleset.technologies.find(t => t.name === impliedName);
    if (!impliedTech) continue;
    const implied = {
      name: impliedTech.name,
      categories: impliedTech.categories,
      website: impliedTech.website || null,
      verified: !!impliedTech.verified,
      implies: [],
      version: null,
      confidence: Math.min(30, Math.round(f.confidence * 0.4)),
      evidence: [{ signal: `implied-by:${f.name}`, matched: f.name, confidence: 0 }],
      vulnerabilities: [],
      inferred: true
    };
    findings.push(implied);
    byName.set(impliedName, implied);
  }

  // favicon-hash match: merges into an existing finding's evidence/confidence
  // if that technology was already detected some other way, otherwise adds
  // a standalone finding sourced purely from the hash match.
  const faviconMatch = evalFaviconSignal(evidence.faviconHash, faviconDb);
  if (faviconMatch) {
    const existing = byName.get(faviconMatch.techName);
    if (existing) {
      existing.evidence.push({ signal: faviconMatch.signal, matched: faviconMatch.matched, confidence: faviconMatch.confidence });
      existing.confidence = Math.min(100, existing.confidence + faviconMatch.confidence);
    } else {
      const knownTech = ruleset.technologies.find(t => t.name === faviconMatch.techName);
      const favFinding = {
        name: faviconMatch.techName,
        categories: knownTech ? knownTech.categories : ['Unknown'],
        website: knownTech ? knownTech.website || null : null,
        verified: knownTech ? !!knownTech.verified : false,
        custom: false,
        implies: [],
        version: null,
        confidence: faviconMatch.confidence,
        evidence: [{ signal: faviconMatch.signal, matched: faviconMatch.matched, confidence: faviconMatch.confidence }],
        vulnerabilities: []
      };
      findings.push(favFinding);
      byName.set(faviconMatch.techName, favFinding);
    }
  }

  findings.sort((a, b) => b.confidence - a.confidence);
  return findings;
}

if (typeof module !== 'undefined') {
  module.exports = { evaluate, versionInRange, compareVersions, findVulnerabilities, versionsConflict };
}
