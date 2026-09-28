<p align="center">
  <img src="doc/top-banner.svg" alt="ISA — Integrated Stack Analyzer" width="100%" />
</p>

<p align="center">
  <img src="doc/logo.svg" alt="ISA logo" width="180" />
</p>

<h1 align="center">ISA — Integrated Stack Analyzer</h1>

<p align="center">
  <img src="doc/status-build-passing.svg" alt="build passing" />
  <img src="doc/status-manifest-v3.svg" alt="manifest v3" />
  <img src="doc/status-chrome-extension.svg" alt="chrome extension" />
  <img src="doc/status-license-mit.svg" alt="license MIT" />
  <img src="doc/status-version.svg" alt="version 1.0.0" />
</p>

<p align="center">
  A Chrome extension (Manifest V3) for <b>evidence-based</b> technology fingerprinting<br/>
  and version enumeration — think Wappalyzer / WhatWeb, but <b>better</b>.
</p>

<p align="center">
  <img src="doc/glitch-title.svg" alt="ISA" width="360" />
</p>

<p align="center">
  <img src="doc/warning-banner.svg" alt="Authorized recon only" width="100%" />
</p>

<br/>

## <img src="doc/toc-icon.svg" width="20" valign="middle" /> Table of contents

- [What ISA is](#what-isa-is)
- [Feature overview](#feature-overview)
- [Live snapshot](#live-snapshot)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Detection engine — how it works](#detection-engine--how-it-works)
- [Evidence sources currently wired up](#evidence-sources-currently-wired-up)
- [The `verified` flag](#the-verified-flag)
- [CVE, KEV &amp; exploit-intel correlation](#cve-kev--exploit-intel-correlation)
- [Privacy &amp; permissions](#privacy--permissions)
- [Build &amp; packaging](#build--packaging)
- [Publishing to the Chrome Web Store](#publishing-to-the-chrome-web-store)
- [Honesty section: limits &amp; not-yet-tested](#honesty-section-limits--not-yet-tested)
- [Contributing](#contributing)
- [License](#license)

<p align="center"><img src="doc/divider-circuit.svg" width="100%" alt="" /></p>

## What ISA is

**ISA (Integrated Stack Analyzer)** is a browser-based recon tool built for
**authorized** penetration tests and bug-bounty engagements. It watches a page
the way a human analyst would — headers, cookies, meta tags, script sources,
CSS custom properties, CSP allow-lists, live JS globals, and outbound API
calls — and turns what it sees into a fingerprint you can actually trust,
because every single line of output is backed by the **raw evidence string**
that produced it.

> **Only run this against targets you're authorized to test.** ISA is a
> magnifying glass, not a weapon — it never runs exploit code and never
> touches anything but the page it's pointed at.

<p align="center"><img src="doc/data-flow-mini.svg" width="420" alt="DOM → NET → CVE → Report" /></p>

<p align="center"><img src="doc/divider-wave.svg" width="100%" alt="" /></p>

## Feature overview

<table align="center"><tr>
<td><img src="doc/feature-card-evidence.svg" width="300" alt="Raw evidence" /></td>
<td><img src="doc/feature-card-confidence.svg" width="300" alt="Confidence score" /></td>
</tr><tr>
<td><img src="doc/feature-card-cve.svg" width="300" alt="CVE correlation" /></td>
<td><img src="doc/feature-card-recon.svg" width="300" alt="Recon-first" /></td>
</tr></table>

| | |
|---|---|
| **Raw evidence** | Every finding comes with the exact matched header, cookie, meta tag, script path or DOM string — click to expand and verify it yourself. |
| **Confidence score** | The sum of every independent signal that actually matched, capped at 100. No category guesswork, ever. |
| **CVE correlation** | Detected `technology + exact version` pairs are checked against a local advisory table, then optionally against NVD, OSV.dev, GHSA, CISA KEV and FIRST.org EPSS. |
| **Recon-first design** | Read-only by default. Every network call beyond the target page itself is opt-in and documented in `PRIVACY.md`. |

<p align="center"><img src="doc/divider-scan.svg" width="100%" alt="" /></p>

## Live snapshot

This is what a completed scan looks like — findings, evidence, and severity,
all in one popup:

<p align="center"><img src="doc/terminal-typing.svg" width="480" alt="isa scan terminal" /></p>

<p align="center"><img src="doc/stats-dashboard.svg" width="100%" alt="scan stats" /></p>

<p align="center">
  <img src="doc/confidence-gauge.svg" width="180" alt="confidence gauge" />
  <img src="doc/radar-scan.svg" width="180" alt="radar scan" />
  <img src="doc/progress-bar-animated.svg" width="380" alt="evidence collection progress" valign="middle" />
</p>

<p align="center"><img src="doc/divider-circuit.svg" width="100%" alt="" /></p>

## Screenshots

Real captures from a real Chromium instance running against real scan data
(via `tools/screenshot-ui.py`) — not mockups.

<table align="center">
<tr>
<td align="center" width="50%">
  <img src="doc/popup-collapsed.png" alt="Popup after a scan, findings list" width="100%"/><br/>
  <sub><b>Popup — findings list</b><br/>Risk score, header grade, exposure checks, and every detected technology with its confidence bars.</sub>
</td>
<td align="center" width="50%">
  <img src="doc/popup-expanded.png" alt="A finding row expanded, showing evidence" width="100%"/><br/>
  <sub><b>Popup — evidence expanded</b><br/>WordPress finding opened up: the exact <code>meta:generator</code> match, confidence math, and per-finding CVE lookup buttons.</sub>
</td>
</tr>
<tr>
<td align="center" width="50%">
  <img src="doc/popup-live-cve-failure-state.png" alt="Live CVE lookup error state" width="100%"/><br/>
  <sub><b>Popup — live-lookup error state</b><br/>What "NVD returned 403" looks like in the real UI — a clear, specific error rather than a hang or a stack trace.</sub>
</td>
<td align="center" width="50%">
  <img src="doc/options.png" alt="Custom fingerprint rule builder" width="100%"/><br/>
  <sub><b>Options — custom fingerprint rules</b><br/>Build your own signal-based rules (header, cookie, meta, script-src, requestUrl, global, DOM, CSS var, CSP domain) for anything outside the 188+ built-in technologies.</sub>
</td>
</tr>
<tr>
<td align="center" width="50%">
  <img src="doc/history.png" alt="Scan history table" width="100%"/><br/>
  <sub><b>Scan history</b><br/>Every origin ISA has scanned this session, local-only, exportable as CSV or full JSON.</sub>
</td>
<td align="center" width="50%">
  <img src="doc/cws-listing-popup-1280x800.png" alt="Chrome Web Store listing screenshot" width="100%"/><br/>
  <sub><b>Store-listing asset</b><br/>The popup at the exact 1280×800 size the Chrome Web Store requires for listing screenshots.</sub>
</td>
</tr>
</table>

<p align="center"><img src="doc/divider-circuit.svg" width="100%" alt="" /></p>

## Installation

<img src="doc/section-header-install.svg" width="100%" alt="Installation" />

**Unpacked, for development:**

1. Open `chrome://extensions` → enable **Developer mode**.
2. Click **Load unpacked** → select the `isa-extension` folder.
3. Visit any site you're authorized to test, then click the ISA icon in the toolbar.

**Verifying it actually works, without needing a real target yet:**

```bash
node tools/serve-fixture.mjs
```

Then visit `http://localhost:8420/` with ISA loaded, open the popup, and
compare the output against `test-fixture/EXPECTED.md` — a synthetic page that
exercises nearly every signal type (headers, cookies, meta tags, script
sources, CSS custom properties, CSP domains, inline HTML, and DOM selectors)
against a ground-truth result list generated by running the *real* matcher —
not hand-guessed. It can't exercise `globals` or `requestUrl` signals, since
those need a live JS runtime and live network observation respectively;
`EXPECTED.md` says so explicitly and names exactly which fixture
technologies it under-reports for that reason.

<p align="center"><img src="doc/divider-wave.svg" width="100%" alt="" /></p>

## Usage

<img src="doc/section-header-usage.svg" width="100%" alt="Usage" />

<p align="center"><img src="doc/evidence-pipeline.svg" width="100%" alt="Recon → Enumerate → Correlate → Report" /></p>

1. **Recon** — load the target page with ISA active; the content script and
   background worker begin collecting raw signals immediately, passively.
2. **Enumerate** — `lib/matcher.js` turns matched signals into named
   technologies with an exact (or best-available) version string.
3. **Correlate** — matched `technology + version` pairs are checked against
   the local vulnerability table, and optionally against live feeds.
4. **Report** — review results in the popup, drill into evidence per
   finding, and export as JSON, CSV, Markdown, or SARIF 2.1.0 for CI
   ingestion (GitHub Code Scanning, GitLab, Azure DevOps).

<p align="center"><img src="doc/divider-scan.svg" width="100%" alt="" /></p>

## Detection engine — how it works

<img src="doc/section-header-detection.svg" width="100%" alt="Detection engine" />

Every technology entry in `lib/technologies.json` declares one or more
**signals**: an HTTP response-header regex, a cookie-name regex, a
`<meta name=generator>` pattern, a script-`src` path pattern, an
inline-HTML/comment pattern, a live `window.*` global read from the page's
own JS context, or a DOM selector/attribute. `lib/matcher.js` only reports a
technology when **at least one signal actually matched** — nothing is ever
inferred from category guesswork.

Each technology's overall **confidence** score is the sum of every signal
that matched (capped at 100), and the popup shows the exact matched string
behind every signal so you can hand-verify it yourself.

Version numbers are pulled from regex capture groups or read directly off a
live object (`jQuery.fn.jquery`, `React.version`, …) — never guessed from a
technology's mere presence.

<p align="center"><img src="doc/architecture-diagram.svg" width="100%" alt="ISA data-collection architecture" /></p>

### Evidence sources currently wired up

<p align="center">
  <img src="doc/tech-badge-nginx.svg" alt="nginx 99%" />
  <img src="doc/tech-badge-apache.svg" alt="apache 96%" />
  <img src="doc/tech-badge-php.svg" alt="php 92%" />
  <img src="doc/tech-badge-react.svg" alt="react 88%" />
  <img src="doc/tech-badge-mysql.svg" alt="mysql 85%" />
  <img src="doc/tech-badge-wordpress.svg" alt="wordpress 78%" />
  <img src="doc/tech-badge-vue.svg" alt="vue 83%" />
  <img src="doc/tech-badge-django.svg" alt="django 90%" />
</p>

| Source | Collected by | Notes |
|---|---|---|
| Response headers | `background.js` via `webRequest.onHeadersReceived` | `main_frame` only, incl. `extraHeaders` |
| Cookies (incl. HttpOnly) | `background.js` via `chrome.cookies.getAll` | merged with `document.cookie` names from the content script |
| `<meta>` tags, script `src` list, HTML/comment sample | `content-script.js` | isolated world, passive DOM read |
| Live JS globals (`React.version`, `jQuery.fn.jquery`, `Shopify.shop`, …) | `background.js` via `chrome.scripting.executeScript({world:"MAIN"})` | content scripts can't see page globals directly — this runs a probe in the page's own JS context |
| XHR / fetch / WebSocket endpoint URLs | `background.js` via `webRequest.onBeforeRequest` | captures real observed API/real-time calls as a `requestUrl` signal — stronger evidence than a static markup mention |
| CSS custom properties | `content-script.js` via `document.styleSheets` (same-origin only) | Bootstrap 5+, Tailwind, Chakra UI, Ant Design, Mantine, Radix, Shoelace, Ionic namespace their CSS vars (`--bs-`, `--chakra-`, …), making this an unusually reliable signal |
| CSP-allowlisted domains | `background.js`, parsed from `Content-Security-Policy` | weighted lower than `requestUrl`/`scriptSrc` — a domain a site *permits* isn't the same evidence as one it's *observed* calling |
| DOM selectors/attributes (`[ng-version]`, `[data-reactroot]`, …) | `content-script.js` | |
| Favicon hash (SHA-256) | `background.js` | matched against `lib/favicon-hashes.json` |
| SPA route changes | `background.js` via `chrome.webNavigation.onHistoryStateUpdated` | keeps ISA accurate as a single-page app navigates without a full reload |

Worth being direct about: no fingerprinting tool, including this one, gets to
100% detection accuracy. A site can strip or spoof headers, run a heavily
patched fork, sit behind a WAF that normalizes every response, or minify away
every version string a regex could catch. What actually moves accuracy up is
what this project does throughout — more independent, corroborating signal
types per technology (the confidence score reflects exactly that), testing
every rule against both a positive control and a plausible false-positive
scenario before it ships, and showing raw evidence behind every finding so
you can verify by hand rather than trust a number. `lib/technologies.json`
currently covers **188 named technologies** (**217** with the optional GPL
pack enabled) — real sites regularly run things outside that list, which is
what the custom rule editor is for.

### The `verified` flag

Every ruleset entry is tagged `"verified": true|false`. `true` means the
signature has been manually confirmed against a live target by this
project's maintainer; `false` means it was imported from public fingerprint
conventions but not yet independently re-confirmed here. The popup shows
this as an amber dot (verified), a grey dot (unverified/imported), or a
dashed dot (inferred via an `implies` relationship, e.g. WordPress implying
PHP) — so you always know how much to trust each line before relying on it.

<p align="center"><img src="doc/divider-circuit.svg" width="100%" alt="" /></p>

## CVE, KEV &amp; exploit-intel correlation

<img src="doc/section-header-cve.svg" width="100%" alt="CVE and exploit intel" />

<p align="center">
  <img src="doc/severity-critical.svg" alt="critical" />
  <img src="doc/severity-high.svg" alt="high" />
  <img src="doc/severity-medium.svg" alt="medium" />
  <img src="doc/severity-low.svg" alt="low" />
</p>

`lib/vuln-db.json` is a small, informational-only table mapping a detected
technology + exact version against public CVE advisories. It contains **no
exploit code** — only advisory IDs, severity, and a one-line summary — and
exists purely to help you prioritize what's worth manually verifying.
Matching is real version-range comparison (`versionInRange` /
`compareVersions` in `lib/matcher.js`), not a name match — a patched version
correctly shows zero CVEs from this table.

**Confirming exploitation status (opt-in): CISA KEV + EPSS.** A version
falling in a CVE's affected range tells you it's *theoretically* vulnerable —
it says nothing about whether that vulnerability is actually being exploited
anywhere. The **"confirm exploitation status"** button cross-references
matched CVE IDs against:

- **CISA's Known Exploited Vulnerabilities catalog** — the US government's
  authoritative, continuously-updated list of CVEs *confirmed* to be
  actively exploited in the wild, including ransomware-campaign usage and
  CISA's remediation due date.
- **FIRST.org's EPSS** — a daily-updated statistical probability (0–100%)
  that a given CVE will be exploited in the next 30 days, with a percentile
  rank against every other scored CVE.

**Live CVE lookup (opt-in).** Each finding with a version has a **"check
live CVEs (NVD)"** button that queries NIST's public National Vulnerability
Database for that exact technology + version and shows current CVE IDs,
descriptions, and CVSS scores, plus deep links to NVD, MITRE, Exploit-DB, and
GitHub Security Advisories. Opt-in for two reasons: NVD's public API has a
real rate limit, and it's the one place in ISA that sends data to a server
other than the site you're scanning — see `PRIVACY.md`. **It deliberately
does not fetch, embed, or display exploit code or proof-of-concept content**
— only the links to go look, the same boundary the rest of this project
holds.

Two further opt-in correlation sources round this out: **`lib/osv-lookup.js`**
queries Google's OSV.dev by package name + ecosystem + version rather than by
CVE ID, and **`lib/cpe-lookup.js`** (experimental) does precise CPE-based NVD
matching for a small, individually-confirmed set of technologies.

<p align="center"><img src="doc/divider-wave.svg" width="100%" alt="" /></p>

## Privacy &amp; permissions

<img src="doc/section-header-privacy.svg" width="100%" alt="Privacy and permissions" />

ISA is read-only by design. Everything it collects comes from the page you
already loaded; nothing is sent anywhere unless you explicitly click an
opt-in live-lookup button (NVD, OSV.dev, GHSA, CISA KEV, FIRST.org EPSS).
See `PRIVACY.md` for the full, user-facing privacy policy text and
`CWS_SUBMISSION.md` for the permission justifications used for Chrome Web
Store review.

<p align="center"><img src="doc/divider-scan.svg" width="100%" alt="" /></p>

## Build &amp; packaging

<img src="doc/section-header-build.svg" width="100%" alt="Build and packaging" />

```bash
./build.sh
```

<p align="center">
  <img src="doc/loading-spinner.svg" width="40" alt="" />
  <img src="doc/loading-dots.svg" width="70" alt="" valign="middle" />
</p>

`build.sh` validates every JSON file, syntax-checks every JS file, runs
`tools/lint-rules.mjs` (including its cross-file global-scope-collision
check), runs `tools/self-consistency-check.mjs` (derives a real example from
every regex-based signal and confirms it actually fires through the real
matcher), runs `tools/verify-package.mjs` (confirms every
manifest/HTML/`getURL`/icon reference resolves), runs the full Node.js
regression suite, then runs the real-browser smoke test
(`tests/browser-smoke.py` — advisory-skips if Playwright/Xvfb aren't
available, otherwise enforced) — and only then zips a distributable package
to `dist/isa-extension.zip`. It **refuses to package** if any required check
fails. Ships only runtime files + `README.md` / `LICENSE` / `PRIVACY.md`;
dev-only `tests/`, `tools/`, `test-fixture/`, and `CWS_SUBMISSION.md` stay in
the source tree but aren't bundled into the package.

### Publishing to the Chrome Web Store

See `CWS_SUBMISSION.md` for ready-to-paste permission justifications and the
single-purpose description CWS review requires, and `PRIVACY.md` for the
user-facing privacy-policy text (CWS requires a hosted URL for this).

<p align="center"><img src="doc/divider-circuit.svg" width="100%" alt="" /></p>

## Honesty section: limits &amp; not-yet-tested

This project keeps an explicit, running account of what's been verified and
what hasn't, rather than implying more confidence than the evidence
supports. `chrome.webNavigation.onHistoryStateUpdated` (SPA route changes)
and `webRequest`-based header/cookie capture are covered by
`tests/browser-smoke.py` against a real Chromium instance. **Not yet
covered by any automated test:** the `chrome.scripting` MAIN-world global
probe (`enrichGlobals`) — exercising it for real needs an actual third-party
script (jQuery, React, …) to execute and set those globals, and this
project's build/test environment has no outbound internet access to fetch
one. Worth hand-verifying against a real, versioned library once you load
the unpacked extension somewhere with real internet access.

<p align="center"><img src="doc/divider-wave.svg" width="100%" alt="" /></p>

## Contributing

<img src="doc/section-header-contributing.svg" width="100%" alt="Contributing" />

Contributions that add a new detection signal should include: the first-party
source you confirmed it against, a positive-control test, and — where a
false-positive is plausible — a negative-control test too. Run `./build.sh`
before opening a PR; it will refuse to package (and CI will fail) if lint,
self-consistency, or the regression suite don't pass clean.

<p align="center"><img src="doc/divider-scan.svg" width="100%" alt="" /></p>

## License

<img src="doc/section-header-license.svg" width="100%" alt="License" />

<p align="center"><img src="doc/status-license-mit.svg" alt="MIT license" /></p>

See `LICENSE` for the full text, and `GPL-PACK-NOTICE.md` for licensing
notes on the optional extended technologies pack.

<p align="center"><img src="doc/footer-signature.svg" width="560" alt="" /></p>

<p align="center">
  <img src="doc/bottom-banner.svg" alt="ISA — Integrated Stack Analyzer" width="100%" />
</p>
