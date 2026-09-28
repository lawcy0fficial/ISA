/**
 * ISA — active exposure checks.
 * These make additional read-only GET requests to the target origin, so
 * unlike everything else in ISA they are NOT run automatically — the popup
 * only triggers this on an explicit button press. No write requests, no
 * exploitation, no credentials submitted. Only presence/shape of the
 * response is reported; secret *values* (e.g. .env contents) are never
 * surfaced beyond a redacted key-name preview.
 */

async function fetchText(url, timeoutMs = 4000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { signal: controller.signal, credentials: 'omit' });
    const text = resp.ok ? await resp.text() : '';
    return { ok: resp.ok, status: resp.status, text };
  } catch {
    return { ok: false, status: 0, text: '' };
  } finally {
    clearTimeout(t);
  }
}

function redactEnvKeys(text) {
  return text
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && l.includes('='))
    .map(l => l.split('=')[0])
    .slice(0, 12);
}

async function checkGitExposure(origin) {
  const head = await fetchText(`${origin}/.git/HEAD`);
  if (head.ok && /^ref:\s*refs\//.test(head.text.trim())) {
    const config = await fetchText(`${origin}/.git/config`);
    return {
      id: 'git-exposure',
      severity: 'critical',
      title: 'Exposed .git directory',
      detail: `/.git/HEAD is publicly readable (${head.text.trim()}). A full source-code history dump may be reconstructable.`,
      configExposed: config.ok && /\[core\]/.test(config.text)
    };
  }
  return null;
}

async function checkEnvExposure(origin) {
  const env = await fetchText(`${origin}/.env`);
  if (env.ok && /^[A-Z0-9_]+=/m.test(env.text)) {
    return {
      id: 'env-exposure',
      severity: 'critical',
      title: 'Exposed .env file',
      detail: `/.env is publicly readable. Key names present (values redacted): ${redactEnvKeys(env.text).join(', ')}`
    };
  }
  return null;
}

function extractPackageNames(sourcePaths) {
  // Real recon value beyond "N files exposed": a webpack/rollup source map's
  // 'sources' array typically includes paths like
  // "webpack://app/./node_modules/react-dom/cjs/react-dom.development.js",
  // which reveals the exact dependency name (and sometimes version, if the
  // bundler's path includes it) without needing the library to have been
  // separately fingerprinted via any other signal.
  const packages = new Set();
  const re = /node_modules\/((?:@[^/]+\/)?[^/]+)\//g;
  for (const src of sourcePaths) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(src))) packages.add(m[1]);
  }
  return [...packages].sort();
}

async function checkSourceMaps(origin, scriptSrcs) {
  const findings = [];
  const candidates = (scriptSrcs || []).slice(0, 15);
  for (const src of candidates) {
    let absUrl;
    try { absUrl = new URL(src, origin).href; } catch { continue; }
    if (new URL(absUrl).origin !== origin) continue; // stick to first-party assets
    const script = await fetchText(absUrl);
    if (!script.ok) continue;
    const m = /\/\/[#@]\s*sourceMappingURL=([^\s]+)/.exec(script.text);
    if (!m) continue;
    let mapUrl;
    try { mapUrl = new URL(m[1], absUrl).href; } catch { continue; }
    const map = await fetchText(mapUrl);
    if (map.ok) {
      try {
        const parsed = JSON.parse(map.text);
        if (Array.isArray(parsed.sources)) {
          const packages = extractPackageNames(parsed.sources);
          const detailParts = [`${mapUrl} is publicly readable, revealing ${parsed.sources.length} original source path(s), e.g.: ${parsed.sources.slice(0, 4).join(', ')}`];
          if (packages.length) {
            detailParts.push(`Bundled npm packages identified from the paths: ${packages.slice(0, 15).join(', ')}${packages.length > 15 ? `, +${packages.length - 15} more` : ''}.`);
          }
          findings.push({
            id: `sourcemap:${absUrl}`,
            severity: 'medium',
            title: 'Exposed source map',
            detail: detailParts.join(' '),
            packages
          });
        }
      } catch { /* not valid JSON — skip */ }
    }
  }
  return findings;
}

async function checkDependencyManifests(origin) {
  // Misconfigured static file serving occasionally exposes a project's own
  // dependency manifest at the web root. Unlike every other version signal
  // in ISA (regex-extracted from a filename or a live global), this gives
  // an EXACT declared version straight from the source of truth — real
  // recon value, not an approximation.
  const findings = [];

  const pkg = await fetchText(`${origin}/package.json`);
  if (pkg.ok) {
    try {
      const parsed = JSON.parse(pkg.text);
      if (parsed && (parsed.dependencies || parsed.devDependencies || parsed.name)) {
        const deps = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };
        const depList = Object.entries(deps).slice(0, 30).map(([name, ver]) => `${name}@${ver}`);
        findings.push({
          id: 'manifest:package.json', severity: 'medium', title: 'Exposed package.json',
          detail: `/package.json is publicly readable${parsed.name ? ` (project: ${parsed.name}${parsed.version ? `@${parsed.version}` : ''})` : ''}. Declared dependencies with exact version ranges: ${depList.join(', ') || 'none listed'}${Object.keys(deps).length > 30 ? `, +${Object.keys(deps).length - 30} more` : ''}.`
        });
      }
    } catch { /* not valid JSON — not actually a package.json, skip */ }
  }

  const composerLock = await fetchText(`${origin}/composer.lock`);
  if (composerLock.ok) {
    try {
      const parsed = JSON.parse(composerLock.text);
      if (Array.isArray(parsed.packages)) {
        const pkgs = parsed.packages.slice(0, 30).map(p => `${p.name}@${p.version}`);
        findings.push({
          id: 'manifest:composer.lock', severity: 'medium', title: 'Exposed composer.lock',
          detail: `/composer.lock is publicly readable, revealing exact resolved PHP package versions: ${pkgs.join(', ')}${parsed.packages.length > 30 ? `, +${parsed.packages.length - 30} more` : ''}.`
        });
      }
    } catch { /* not valid JSON — skip */ }
  }

  const gemfileLock = await fetchText(`${origin}/Gemfile.lock`);
  if (gemfileLock.ok && /^GEM$/m.test(gemfileLock.text)) {
    const gemLines = [...gemfileLock.text.matchAll(/^ {4}([a-zA-Z0-9_-]+) \(([0-9][^)]*)\)$/gm)]
      .slice(0, 30).map(m => `${m[1]}@${m[2]}`);
    if (gemLines.length) {
      findings.push({
        id: 'manifest:Gemfile.lock', severity: 'medium', title: 'Exposed Gemfile.lock',
        detail: `/Gemfile.lock is publicly readable, revealing exact resolved Ruby gem versions: ${gemLines.join(', ')}.`
      });
    }
  }

  const requirementsTxt = await fetchText(`${origin}/requirements.txt`);
  if (requirementsTxt.ok && /^[a-zA-Z0-9_.-]+==[0-9]/m.test(requirementsTxt.text)) {
    const pyLines = [...requirementsTxt.text.matchAll(/^([a-zA-Z0-9_.-]+)==([0-9][^\s#]*)/gm)]
      .slice(0, 30).map(m => `${m[1]}@${m[2]}`);
    findings.push({
      id: 'manifest:requirements.txt', severity: 'medium', title: 'Exposed requirements.txt',
      detail: `/requirements.txt is publicly readable, revealing exact pinned Python package versions: ${pyLines.join(', ')}.`
    });
  }

  return findings;
}

async function checkWordPressReadme(origin) {
  // WordPress's own default readme.html at the site root has stated its
  // exact core version in plain text since the project began — a classic,
  // well-known recon technique, and a genuinely authoritative version
  // signal (straight from the source) rather than an inferred one.
  const readme = await fetchText(`${origin}/readme.html`);
  if (!readme.ok) return null;
  const m = /Version\s+([0-9]+(?:\.[0-9]+){1,2})/i.exec(readme.text);
  if (!m || !/WordPress/i.test(readme.text)) return null;
  return {
    id: 'wp-readme', severity: 'low', title: 'WordPress core version confirmed via /readme.html',
    detail: `/readme.html publicly confirms WordPress ${m[1]} — an authoritative version straight from WordPress's own default file, not inferred from a script path or meta tag.`
  };
}

// Framework/language debug-mode signatures. Each is checked against the
// body of a request to a path that should not exist on any real site
// (a random suffix, so this can never collide with an actual route) — the
// exact same kind of GET request a browser makes for any 404, just with a
// deliberately-unguessable path. If the app is in debug/development mode,
// its own default error handler often dumps a stack trace, file paths, or
// framework version straight into that response. This is informational
// recon (confirms debug mode is live in production) — ISA never sends
// anything crafted to *trigger* an error beyond a plain GET to a
// nonexistent path, which is categorically different from fuzzing input
// to provoke one.
const DEBUG_PAGE_SIGNATURES = [
  { id: 'laravel-whoops', re: /<title>[^<]*Whoops[^<]*<\/title>|"stack":\s*\[|Illuminate\\\\/i, label: 'Laravel (Whoops debug page)' },
  { id: 'django-debug', re: /You're seeing this error because you have <code>DEBUG = True<\/code>|Django Version:\s*[\d.]+/i, label: 'Django (DEBUG=True error page)' },
  { id: 'flask-werkzeug', re: /Werkzeug Debugger|The debugger caught an exception in your WSGI application/i, label: 'Flask/Werkzeug interactive debugger' },
  { id: 'rails-debug', re: /ActionController::RoutingError|Rails\.root|app\/controllers\/.*\.rb:\d+/i, label: 'Ruby on Rails (detailed exception page)' },
  { id: 'aspnet-yellow', re: /Server Error in '\/' Application|\[HttpException[^\]]*\]|Version Information:\s*Microsoft \.NET Framework/i, label: 'ASP.NET (Yellow Screen of Death)' },
  { id: 'php-fatal', re: /Fatal error:.*in\s+\/[\w./-]+\.php on line \d+|<b>Warning<\/b>:.*in <b>\/[\w./-]+\.php<\/b>/i, label: 'PHP (uncaught error with full server path disclosed)' },
  { id: 'spring-whitelabel', re: /Whitelabel Error Page|This application has no explicit mapping for \/error/i, label: 'Spring Boot (Whitelabel error page — confirms the stack, not itself sensitive)' },
  { id: 'nodejs-stack', re: /at Object\.<anonymous>\s*\(\/[\w./-]+:\d+:\d+\)|Error:.*\n\s+at .*\(\/[\w./-]+\.js:\d+:\d+\)/, label: 'Node.js (unhandled exception with server file paths disclosed)' }
];

async function checkVerboseErrors(origin) {
  const probe = `${origin}/isa-debug-probe-${Math.random().toString(36).slice(2, 10)}`;
  const resp = await fetchText(probe, 5000);
  if (!resp.text) return null;
  const hit = DEBUG_PAGE_SIGNATURES.find(sig => sig.re.test(resp.text));
  if (!hit) return null;
  return {
    id: `debug-page:${hit.id}`,
    severity: 'medium',
    title: 'Verbose error page exposed',
    detail: `A request to a nonexistent path returned a ${hit.label} response (HTTP ${resp.status}), indicating debug/development mode may be active in production. Depending on the framework this can disclose file paths, source snippets, environment details, or framework/library versions to any visitor who triggers an error.`
  };
}

// Common static-asset directories where autoindex/directory-listing is
// most often left enabled by accident. Checks the standard Apache/Nginx
// "Index of /" autoindex HTML pattern — a plain GET, same as clicking the
// link in a browser.
const LISTING_CANDIDATE_PATHS = ['/images/', '/uploads/', '/assets/', '/files/', '/backup/', '/wp-content/uploads/', '/static/'];

async function checkDirectoryListing(origin) {
  const findings = [];
  for (const path of LISTING_CANDIDATE_PATHS) {
    const resp = await fetchText(`${origin}${path}`, 4000);
    if (!resp.ok) continue;
    if (/<title>Index of /i.test(resp.text) || /^Index of \//m.test(resp.text.replace(/<[^>]+>/g, ''))) {
      const fileCount = (resp.text.match(/<a href=/gi) || []).length;
      findings.push({
        id: `dir-listing:${path}`,
        severity: 'low',
        title: 'Directory listing enabled',
        detail: `${origin}${path} returns an autoindex directory listing (~${fileCount} linked entries) rather than a 403/404 — the full contents of this directory are browsable.`
      });
    }
  }
  return findings;
}

// RFC 9116 security.txt — informational, not itself a vulnerability, but
// its *absence* is worth surfacing during recon (no disclosed vuln-report
// contact means a researcher has no sanctioned channel), and its presence
// is worth surfacing too (it tells you where to actually report anything
// else ISA finds). Checks the canonical /.well-known/ location first, then
// falls back to the legacy site-root location the RFC deprecated but many
// older sites still only serve.
async function checkSecurityTxt(origin) {
  for (const path of ['/.well-known/security.txt', '/security.txt']) {
    const resp = await fetchText(`${origin}${path}`, 4000);
    if (resp.ok && /Contact\s*:/i.test(resp.text)) {
      const contactLines = resp.text.split('\n').filter(l => /^Contact\s*:/i.test(l.trim())).map(l => l.trim());
      return {
        id: 'security-txt:found',
        severity: 'info',
        title: 'security.txt present',
        detail: `${origin}${path} is published with a vulnerability-disclosure contact (${contactLines.length} contact line${contactLines.length === 1 ? '' : 's'}) — this is the sanctioned channel for reporting anything else ISA finds here, not an issue itself.`
      };
    }
  }
  return {
    id: 'security-txt:missing',
    severity: 'info',
    title: 'No security.txt found',
    detail: `Neither /.well-known/security.txt nor /security.txt is published (RFC 9116). Not a vulnerability, but there's no sanctioned disclosure channel for reporting anything found here.`
  };
}

// robots.txt / sitemap.xml: not a vulnerability to have these — they're
// meant to be public — but Disallow entries routinely name admin panels,
// staging paths, or internal tooling the site owner would rather not
// advertise, and that's exactly what they end up doing by listing them.
// Purely informational attack-surface mapping from two files any browser
// already fetches by convention.
async function checkRobotsAndSitemap(origin) {
  const findings = [];

  const robots = await fetchText(`${origin}/robots.txt`, 4000);
  if (robots.ok && robots.text.trim()) {
    const disallowed = [...new Set(
      robots.text.split('\n')
        .map(l => l.trim())
        .filter(l => /^Disallow\s*:/i.test(l))
        .map(l => l.split(':').slice(1).join(':').trim())
        .filter(p => p && p !== '/')
    )];
    const sitemapUrls = [...new Set(
      robots.text.split('\n')
        .map(l => l.trim())
        .filter(l => /^Sitemap\s*:/i.test(l))
        .map(l => l.split(':').slice(1).join(':').trim())
    )];
    if (disallowed.length) {
      const interesting = disallowed.filter(p => /admin|internal|staging|backup|private|debug|test|api|config/i.test(p));
      findings.push({
        id: 'robots-txt:disallow',
        severity: interesting.length ? 'low' : 'info',
        title: `robots.txt discloses ${disallowed.length} path${disallowed.length === 1 ? '' : 's'}`,
        detail: (interesting.length
          ? `Including ${interesting.length} that look administrative/internal: ${interesting.slice(0, 8).join(', ')}${interesting.length > 8 ? ', …' : ''}. `
          : '') + `Full disallow list: ${disallowed.slice(0, 15).join(', ')}${disallowed.length > 15 ? ', …' : ''}`
      });
    }
    if (sitemapUrls.length) {
      findings.push({
        id: 'robots-txt:sitemap',
        severity: 'info',
        title: `${sitemapUrls.length} sitemap${sitemapUrls.length === 1 ? '' : 's'} declared`,
        detail: sitemapUrls.join(', ')
      });
    }
  }

  return findings;
}

// GraphQL introspection: the introspection query is a completely standard,
// read-only part of the GraphQL spec itself — this sends nothing a normal
// GraphQL client wouldn't send, just the schema-discovery query every
// GraphQL IDE tool issues automatically. Leaving it enabled in production
// is a common, real finding (it hands an attacker the full API surface —
// every type, field, mutation, and argument) without ISA doing anything
// resembling exploitation. Tries the handful of conventional endpoint
// paths since GraphQL has no single standard mount point.
const INTROSPECTION_QUERY = JSON.stringify({ query: '{__schema{queryType{name}mutationType{name}types{name kind}}}' });
const GRAPHQL_CANDIDATE_PATHS = ['/graphql', '/api/graphql', '/graphql/console', '/v1/graphql'];

async function checkGraphQLIntrospection(origin) {
  for (const path of GRAPHQL_CANDIDATE_PATHS) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 4000);
    try {
      const resp = await fetch(`${origin}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: INTROSPECTION_QUERY,
        credentials: 'omit',
        signal: controller.signal
      });
      clearTimeout(t);
      if (!resp.ok) continue;
      const data = await resp.json().catch(() => null);
      const schema = data?.data?.__schema;
      if (schema && Array.isArray(schema.types)) {
        const mutationCount = schema.types.filter(t => t.kind === 'OBJECT').length;
        return {
          id: `graphql-introspection:${path}`,
          severity: 'medium',
          title: 'GraphQL introspection enabled',
          detail: `${origin}${path} answers the standard introspection query and returns the full schema (~${schema.types.length} types) — every type, field, and mutation is discoverable. Introspection is typically disabled in production for APIs that aren't meant to be publicly explorable.`
        };
      }
    } catch {
      clearTimeout(t);
    }
  }
  return null;
}

async function runExposureChecks(origin, scriptSrcs) {
  const results = [];
  const [git, env, maps, manifests, wpReadme, debugPage, listings, securityTxt, robotsSitemap] = await Promise.all([
    checkGitExposure(origin),
    checkEnvExposure(origin),
    checkSourceMaps(origin, scriptSrcs),
    checkDependencyManifests(origin),
    checkWordPressReadme(origin),
    checkVerboseErrors(origin),
    checkDirectoryListing(origin),
    checkSecurityTxt(origin),
    checkRobotsAndSitemap(origin)
  ]);
  if (git) results.push(git);
  if (env) results.push(env);
  results.push(...maps);
  results.push(...manifests);
  if (wpReadme) results.push(wpReadme);
  if (debugPage) results.push(debugPage);
  results.push(...listings);
  if (securityTxt) results.push(securityTxt);
  results.push(...robotsSitemap);
  return results;
}

// GraphQL introspection is intentionally NOT part of runExposureChecks'
// default Promise.all batch — it's a POST rather than a GET, tries several
// paths against ones that may not exist (404 is the overwhelmingly common,
// harmless outcome), and is a meaningfully different risk profile from the
// other checks here (revealing API surface vs. revealing static files).
// Surfaced as its own opt-in action in the popup rather than bundled in.
async function runGraphQLCheck(origin) {
  const result = await checkGraphQLIntrospection(origin);
  return result ? [result] : [];
}

if (typeof module !== 'undefined') {
  module.exports = { runExposureChecks, checkGitExposure, checkEnvExposure, checkSourceMaps, extractPackageNames, checkDependencyManifests, checkWordPressReadme, checkVerboseErrors, checkDirectoryListing, checkSecurityTxt, checkRobotsAndSitemap, checkGraphQLIntrospection, runGraphQLCheck };
}
