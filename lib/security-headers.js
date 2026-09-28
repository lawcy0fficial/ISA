/**
 * ISA — security header grading.
 * Given response headers (+ raw Set-Cookie header values) and, optionally,
 * the page's collected subresource list, returns a per-check pass/weak/
 * missing verdict and an overall letter grade. No network access, no side
 * effects — safe to unit test directly.
 */

function parseCacheableMaxAge(hstsValue) {
  const m = /max-age=(\d+)/i.exec(hstsValue || '');
  return m ? parseInt(m[1], 10) : null;
}

function parseSetCookieFlags(raw) {
  // A Set-Cookie header is "name=value; Attr1; Attr2=val2; ...". Checking
  // the WHOLE raw string for the substring "secure" is wrong — a cookie
  // literally named "insecure_debug_flag" would match "secure" as a
  // substring of "insecure" even with no Secure attribute actually set,
  // artificially inflating a site's grade. Only the attribute segments
  // (after the first ";") should ever be checked, and each checked as a
  // whole trimmed token, not a substring — the same discipline as the
  // exact-word matching used for NVD relevance filtering elsewhere in
  // this project, applied here because it's the same bug class.
  const segments = raw.split(';');
  const nameValue = segments[0] || '';
  const attributes = segments.slice(1).map(s => s.trim().toLowerCase());

  return {
    name: (nameValue.split('=')[0] || '').trim(),
    secure: attributes.includes('secure'),
    httpOnly: attributes.includes('httponly'),
    sameSite: (attributes.find(a => a.startsWith('samesite=')) || '').split('=')[1] || null
  };
}

function gradeHeaders(headers, setCookieHeaders = [], isHttps = true, subresources = null) {
  // Every check pushes its own maxPoints alongside points, and the overall
  // score/grade is just a sum over exactly what got pushed. The previous
  // version instead re-derived each check's max by string-matching on
  // c.header (c.header.startsWith('X-Frame') ? 8 : ...) in a second, entirely
  // separate reduce — a duplicated source of truth that had visibly rotted:
  // the reduce's leading term, `(c.status === 'missing' ? 0 : 0)`, is a
  // no-op in both branches, dead weight left over from what was clearly
  // meant to be conditional logic. Table-driven avoids that class of bug
  // entirely — there's no second place that can silently disagree with the
  // first, and no per-header string to keep in sync when a new check with
  // a new header name is added below (or by anyone extending this file).
  const checks = [];
  const h = {};
  for (const k in headers) h[k.toLowerCase()] = headers[k];

  // Content-Security-Policy
  if (h['content-security-policy']) {
    const csp = h['content-security-policy'];
    const weak = /unsafe-inline|unsafe-eval/i.test(csp);
    checks.push({
      header: 'Content-Security-Policy',
      status: weak ? 'weak' : 'present',
      points: weak ? 5 : 15,
      maxPoints: 15,
      detail: weak
        ? "Present but allows 'unsafe-inline' and/or 'unsafe-eval', which significantly weakens XSS mitigation."
        : 'Present, with no unsafe-inline/unsafe-eval directive found.'
    });
  } else {
    checks.push({ header: 'Content-Security-Policy', status: 'missing', points: 0, maxPoints: 15, detail: 'No CSP — no defense-in-depth against injected script execution.' });
  }

  // Strict-Transport-Security
  if (isHttps) {
    if (h['strict-transport-security']) {
      const maxAge = parseCacheableMaxAge(h['strict-transport-security']);
      const good = maxAge !== null && maxAge >= 15552000; // 180 days
      checks.push({
        header: 'Strict-Transport-Security',
        status: good ? 'present' : 'weak',
        points: good ? 10 : 5,
        maxPoints: 10,
        detail: good ? `max-age=${maxAge}s meets a reasonable minimum.` : `max-age is low or unparsable (${h['strict-transport-security']}).`
      });
    } else {
      checks.push({ header: 'Strict-Transport-Security', status: 'missing', points: 0, maxPoints: 10, detail: 'No HSTS — downgrade/SSL-stripping on future visits is not mitigated by the browser.' });
    }
  }

  // X-Content-Type-Options
  if (/nosniff/i.test(h['x-content-type-options'] || '')) {
    checks.push({ header: 'X-Content-Type-Options', status: 'present', points: 8, maxPoints: 8, detail: 'nosniff set.' });
  } else {
    checks.push({ header: 'X-Content-Type-Options', status: 'missing', points: 0, maxPoints: 8, detail: 'MIME-sniffing not disabled.' });
  }

  // X-Frame-Options / frame-ancestors
  const hasFrameAncestors = /frame-ancestors/i.test(h['content-security-policy'] || '');
  if (h['x-frame-options'] || hasFrameAncestors) {
    checks.push({ header: 'X-Frame-Options / frame-ancestors', status: 'present', points: 8, maxPoints: 8, detail: hasFrameAncestors ? 'Covered via CSP frame-ancestors.' : `Set to: ${h['x-frame-options']}` });
  } else {
    checks.push({ header: 'X-Frame-Options / frame-ancestors', status: 'missing', points: 0, maxPoints: 8, detail: 'No clickjacking protection found.' });
  }

  // Referrer-Policy
  if (h['referrer-policy']) {
    checks.push({ header: 'Referrer-Policy', status: 'present', points: 5, maxPoints: 5, detail: `Set to: ${h['referrer-policy']}` });
  } else {
    checks.push({ header: 'Referrer-Policy', status: 'missing', points: 0, maxPoints: 5, detail: 'Defaults to browser behavior — may leak full referrer URLs cross-origin.' });
  }

  // Permissions-Policy
  if (h['permissions-policy']) {
    checks.push({ header: 'Permissions-Policy', status: 'present', points: 4, maxPoints: 4, detail: 'Present — restricts powerful browser features.' });
  } else {
    checks.push({ header: 'Permissions-Policy', status: 'missing', points: 0, maxPoints: 4, detail: 'Not set — informational only.' });
  }

  // Set-Cookie hygiene
  if (setCookieHeaders.length) {
    const parsed = setCookieHeaders.map(parseSetCookieFlags);
    const bad = parsed.filter(c => !c.secure || !c.httpOnly || !c.sameSite);
    checks.push({
      header: 'Set-Cookie flags',
      status: bad.length === 0 ? 'present' : 'weak',
      points: bad.length === 0 ? 10 : Math.max(0, 10 - bad.length * 3),
      maxPoints: 10,
      detail: bad.length === 0
        ? `All ${parsed.length} cookie(s) set Secure, HttpOnly, and SameSite.`
        : `${bad.length}/${parsed.length} cookie(s) missing Secure/HttpOnly/SameSite: ${bad.map(c => c.name).join(', ')}`
    });
  }

  // CORS misconfiguration — Access-Control-Allow-Origin: * combined with
  // Access-Control-Allow-Credentials: true is a spec-invalid combination
  // (browsers reject it outright for actual credentialed requests), but it
  // still reliably indicates careless CORS configuration worth flagging.
  // What this check deliberately does NOT claim: whether the server
  // *reflects* an arbitrary Origin header back (the more exploitable
  // variant) — confirming that needs sending a second request with a
  // different Origin and comparing, which is active probing outside what a
  // single passive read of the main document's own response headers can
  // tell you. Only pushed when CORS headers are actually present on this
  // response, since their absence on a plain HTML document is completely
  // normal and not a finding.
  const acao = h['access-control-allow-origin'];
  const acac = (h['access-control-allow-credentials'] || '').toLowerCase() === 'true';
  if (acao) {
    const wildcardWithCredentials = acao.trim() === '*' && acac;
    checks.push({
      header: 'CORS (Access-Control-Allow-Origin)',
      status: wildcardWithCredentials ? 'weak' : 'present',
      points: wildcardWithCredentials ? 0 : 6,
      maxPoints: 6,
      detail: wildcardWithCredentials
        ? "Allow-Origin: '*' combined with Allow-Credentials: true is a spec-invalid, misconfigured combination — browsers won't honor it for credentialed requests, but it signals the CORS policy wasn't deliberately designed. Confirming a live reflected-origin bypass needs an active probe, not covered by this passive check."
        : `Set to: ${acao}${acac ? ' (with credentials allowed)' : ''}.`
    });
  }

  // Mixed content — any http:// subresource loaded from an https:// page.
  // Modern browsers already actively block or upgrade most mixed content
  // themselves, so this is a hygiene/staleness signal (an old hardcoded
  // http:// embed) more than a live exploitable gap in most cases — still
  // worth surfacing since it often means an unmaintained third-party embed.
  if (isHttps && Array.isArray(subresources)) {
    const mixed = subresources.filter(r => r.mixedContent);
    if (subresources.length) {
      checks.push({
        header: 'Mixed content',
        status: mixed.length === 0 ? 'present' : 'weak',
        points: mixed.length === 0 ? 8 : Math.max(0, 8 - mixed.length * 2),
        maxPoints: 8,
        detail: mixed.length === 0
          ? 'No http:// script/stylesheet resources found on this https:// page.'
          : `${mixed.length} resource(s) loaded over plain http:// on an https:// page: ${mixed.slice(0, 5).map(r => r.url).join(', ')}${mixed.length > 5 ? `, +${mixed.length - 5} more` : ''}.`
      });
    }
  }

  // Missing Subresource Integrity on cross-origin scripts/stylesheets — a
  // compromised or MITM'd third-party CDN could silently swap the file's
  // contents with nothing to detect it. First-party resources are excluded
  // deliberately: SRI is meant for assets you don't control the delivery
  // of, and flagging a site's own same-origin bundle for lacking SRI would
  // be noise, not a finding.
  if (Array.isArray(subresources)) {
    const thirdParty = subresources.filter(r => r.crossOrigin);
    if (thirdParty.length) {
      const missing = thirdParty.filter(r => !r.hasIntegrity);
      checks.push({
        header: 'Subresource Integrity',
        status: missing.length === 0 ? 'present' : 'weak',
        points: missing.length === 0 ? 6 : Math.max(0, 6 - missing.length),
        maxPoints: 6,
        detail: missing.length === 0
          ? `All ${thirdParty.length} cross-origin script/stylesheet resource(s) have an integrity attribute.`
          : `${missing.length}/${thirdParty.length} cross-origin resource(s) load without an integrity attribute: ${missing.slice(0, 5).map(r => r.url).join(', ')}${missing.length > 5 ? `, +${missing.length - 5} more` : ''}.`
      });
    }
  }

  const totalPoints = checks.reduce((n, c) => n + c.points, 0);
  const maxPoints = checks.reduce((n, c) => n + c.maxPoints, 0);
  const pct = maxPoints > 0 ? totalPoints / maxPoints : 0;

  let grade;
  if (pct >= 0.9) grade = 'A';
  else if (pct >= 0.75) grade = 'B';
  else if (pct >= 0.55) grade = 'C';
  else if (pct >= 0.35) grade = 'D';
  else grade = 'F';

  return { grade, score: totalPoints, maxScore: maxPoints, checks };
}

if (typeof module !== 'undefined') {
  module.exports = { gradeHeaders, parseSetCookieFlags, parseCacheableMaxAge };
}
