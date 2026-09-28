# ISA Methodology

What ISA actually does, in one place, rather than scattered across code
comments. If you're evaluating whether to trust a finding, this is what
that finding is (and isn't) backed by.

## The core principle

A finding is only ever produced from **evidence that actually matched**.
Nothing is inferred from category guesswork, and no technology is reported
just because it's common or because the site "looks like" it might use it.
Every finding carries its raw evidence, so you can verify by hand instead
of trusting a number.

## Evidence sources (11 signal types)

| # | Signal | Collected by | What it proves |
|---|---|---|---|
| 1 | HTTP response headers | `background.js` via `webRequest.onHeadersReceived` | Server explicitly identified itself (`Server`, `X-Powered-By`) or a framework-specific header is present |
| 2 | Cookies (incl. HttpOnly) | `background.js` via `chrome.cookies.getAll` | A session/tracking cookie with a framework-specific naming convention was set |
| 3 | `<meta>` tags | `content-script.js` | A `generator` or similar meta tag names the technology directly |
| 4 | Script `src` paths | `content-script.js` | A loaded script's path or filename matches a known library/CDN pattern |
| 5 | XHR/fetch/WebSocket endpoint URLs | `background.js` via `webRequest.onBeforeRequest` | A real observed request (API call or real-time connection) went to a known endpoint — catches integrations invisible to static markup |
| 6 | Inline HTML/script text | `content-script.js` | A comment, inline script, or markup pattern specific to the technology is present in the rendered page |
| 7 | Live JS globals | `background.js` via `chrome.scripting.executeScript({world:"MAIN"})` | The page's own JS runtime actually has `window.X` set — the strongest signal type, since it reads real runtime state, not a static guess. Content scripts run in an isolated world and can't see page globals directly, hence the separate MAIN-world probe. |
| 8 | DOM selectors/attributes | `content-script.js` | A specific element/attribute pattern (e.g. `[ng-version]`) is present in the rendered DOM |
| 9 | Favicon hash | `background.js`, SHA-256 of favicon bytes | The exact favicon file matches a known default-install fingerprint — useful for admin panels that don't otherwise expose a version string. Ships with an empty lookup table (see `tools/README.md`) since populating it requires real samples, not guesses. |
| 10 | CSS custom properties | `content-script.js` via `document.styleSheets` | A namespaced custom property (`--chakra-`, `--bs-`) specific to a component framework is defined — reliable because frameworks deliberately namespace these to avoid collisions |
| 11 | CSP-allowlisted domains | `background.js`, parsed from `Content-Security-Policy` header | A domain the site permits scripts/connections to/from matches a known service — weaker evidence than an observed request, so kept as a separately-labeled, lower-weighted signal rather than blended into #5 |

Two more evidence sources exist but are **opt-in only**, not part of normal
scanning, because they go beyond passive observation of the page already
loaded:

- **Exposure checks** (`lib/exposure-checks.js`): read-only requests to `/.git/HEAD`, `/.env`, and exposed source maps — the latter now also extracts actual npm package names from `node_modules/` paths in the source map, not just a file count.
- **Live CVE lookup** (`lib/live-cve-lookup.js`): queries NIST's public NVD API for a detected technology + version. The only ISA feature that sends data anywhere besides the site being scanned.

## Confidence model

Every matched signal carries a **confidence weight** (1–100) set when the
rule was authored. A technology's overall confidence is the **sum of every
signal that matched, capped at 100**. This is deliberately simple and
interpretable rather than a black-box scoring model — you can read the
evidence log and see exactly which signals contributed how much, and add
them up yourself if you want to sanity-check the total.

Design rules that keep this honest:

- **A single weak/generic signal should never alone reach high confidence.** A bare common word or a generic bundler output path is capped around 10–20; only corroborating signals push a finding toward "trust this."
- **Weaker evidence types get lower weights even for a specific match.** A CSP-allowlisted domain is deliberately weighted lower than the same domain appearing in an actual `<script src>` or observed request, because permitting isn't the same as using.
- **Live runtime state (JS globals with real version properties) gets the highest individual weights (typically 85–90)**, since it's the closest thing to ground truth ISA can observe from a browser extension.
- **Implied technologies get reduced confidence automatically** (`min(30, round(sourceConfidence * 0.4))`) and are tagged `inferred: true` in the UI — WordPress implying PHP isn't the same strength of claim as detecting PHP directly.

## Version extraction

Versions are **never a static lookup**. Every version shown is pulled from
a regex capture group against real evidence (a header value, a live global
property, a URL path) at scan time. This means version accuracy is
inherently "up to date" by construction — there's no hardcoded version
table to go stale. What can go wrong instead: the technology isn't
detected at all (coverage gap), or a version string is present but doesn't
match the expected pattern (regex gap) — both are accuracy problems this
methodology is built to catch early, not silently ship.

## Verification discipline

Every rule added to this project — 217 technologies across two files as of
this writing — goes through the same pipeline before being considered done:

1. **`node tools/lint-rules.mjs`** — static analysis catching known bug
   shapes: bare generic-word signals with real confidence, `globals`
   signals referencing a path never actually probed, malformed regex,
   duplicate names, dangling `implies` references. Exits non-zero on any
   ERROR.
2. **`node tools/self-consistency-check.mjs`** — auto-generates a literal
   example from every regex-based signal (not just the ones simple enough
   to safely skip the hard cases) and confirms it actually triggers the
   technology it belongs to when run through the real matcher. Blocking —
   all 284 regex-based signals across both files pass as of this writing.
   The derivation tool itself needed one real fix (an anchor-handling bug)
   plus a separate, more important fix to stop it silently skipping any
   signal-type key it didn't recognize — see the incident log below for
   what that process actually found and how each was confirmed, not just
   assumed fixed.
3. **`node tools/verify-package.mjs`** — a category none of the above
   catch: whether the extension would actually *load* in Chrome at all.
   Confirms every file `manifest.json` references exists, every
   script/stylesheet path inside each HTML file resolves relative to that
   file's own directory, every `chrome.runtime.getURL(...)` string literal
   in `background.js` points at a real packaged file, and each icon's
   actual PNG pixel dimensions (read from the raw file header, no image
   library needed) match what `manifest.json` declares for it. Unit tests
   can pass perfectly while a typo'd icon path or a renamed file silently
   breaks the actual load — this is the check for that category of bug,
   proven by deliberately breaking a manifest reference, confirming the
   checker catches it and exits non-zero, then restoring it.
4. **`node tests/run.mjs`** — the regression suite. Every batch of
   additions gets at least one positive-control test (real evidence
   detects correctly, versions extract correctly) and, where the addition
   risked a new false-positive class, a specific test proving it doesn't
   over-match.
5. **A dedicated false-positive check whenever a new signal *type* is
   added** (not just new entries in an existing type) — e.g. when CSS
   custom-property fingerprinting was added, the test suite includes a
   case with plausible ordinary custom property names (`--header-height`)
   confirming they don't accidentally match a framework signal.

All five tools are wired into `build.sh` — lint, self-consistency check,
package integrity, and the regression suite all block the build on
failure; a package literally cannot be produced while any of them fail.

## What this methodology does not, and cannot, achieve

Stated plainly rather than left implicit:

- **Not 100% technology coverage.** 217 technologies is a wide net, not
  every technology that exists. See the README's "On coverage scale"
  section for what real comparable tools (Wappalyzer, BuiltWith) actually
  cover, and why.
- **Not immune to active evasion.** A site that deliberately strips
  identifying headers, obfuscates all version strings, and runs a heavily
  forked/renamed build will evade signature-based detection regardless of
  how many signal types are checked — that's a structural limit of this
  approach, shared by every tool in this category.
- **Confidence is not certainty.** A 100/100 score means multiple
  independent signals corroborated each other, not that the finding is
  guaranteed correct. Always available: the raw evidence log, for you to
  make the final call.

## Bugs this methodology has actually caught (a running record)

Kept here rather than only in commit history, since "we test for this
now" is more convincing with the specific incident attached:

- Two browser-extension-injected JS globals (`__REACT_DEVTOOLS_GLOBAL_HOOK__`, `__REDUX_DEVTOOLS_EXTENSION__`) were being read as page signals — they're set by the *researcher's own installed extensions* on every page, not by the target site, producing guaranteed false positives for any researcher with those tools installed.
- A generic security header (`X-Frame-Options: DENY`) was used as a Django-specific signal.
- A bare keyword match (`graphql` anywhere in page text) was the only GraphQL signal.
- A malformed regex — trivially producible by anyone typing a custom rule in the options page — crashed the *entire* scan for a tab, silently zeroing out detection of all other technologies too, not just the broken one.
- A CSP-domain extractor only recognized `http(s)://` schemes, silently dropping every `wss://`-scheme entry (including the one it was specifically added to catch) — caught by a test that asserted on a specific expected domain rather than just eyeballing a printed array.
- The self-consistency checker itself (`tools/self-consistency-check.mjs`) needed one real fix after being run against the actual ruleset for the first time: its regex-to-literal-example deriver treated `^`/`$` as zero-width anchors only in its top-level loop, not inside a non-capturing group — so the extremely common `(?:^|/)` "start of string or after a slash" prefix (used throughout this ruleset's `scriptSrc` signals) derived a literal caret character into the example instead of nothing, breaking self-consistency for 16 real signals (Three.js, Chart.js, Leaflet, jQuery UI, Axios, and 11 more) in one pass. Fixed by making `^`/`$` zero-width wherever they're read, not just at the top level. A second, structurally different gap was found immediately after by deliberately sabotaging a signal's own top-level key (renaming `scriptSrc` to the typo `scriptSrcs` on a real entry) to check whether the tool would catch it — it didn't: the per-signal-type `evidenceFor()` switch silently returned `null` for any key it didn't recognize, and the caller treated "no evidence to build" as "nothing to check" rather than as a bug in its own right. Fixed by validating every signal-type key against the exact set `lib/matcher.js`'s `evaluate()` actually reads, so a typo'd key that's structurally invisible to the matcher (the same bug *class* as the DOM-selector-drift entry below, just for a different signal type) fails loudly instead of being silently skipped by the checker meant to catch exactly that.
- **`matcher.js` required an exact string match against the ruleset's DOM selector value (including multi-selector strings like `"[data-reactroot], #__next"` as one literal value), but `content-script.js` only ever checked a hardcoded 7-item watchlist that had drifted out of sync since React's very first entry.** 8 technologies' DOM signals — React and Vue.js included — had never once been able to fire, from this project's beginning, because that mismatch predates almost everything else here. Found not by a test, but by actually regenerating a claimed "known good" fixture output by hand instead of trusting the file. Fixed by moving DOM matching into `background.js`, reading selectors dynamically from whatever ruleset is actually loaded via the same `chrome.scripting.executeScript` mechanism already used for the globals probe — self-syncing by construction instead of needing a second list kept in lockstep by hand.
- `collectCssCustomProperties()` (the same-origin stylesheet scan behind the `cssVars` signal) had two compounding gaps: no cap on rules *examined*, only on distinct properties *found* — meaning a stylesheet with thousands of never-repeating property names would iterate unbounded (proved with a 200,000-rule synthetic case where the property-count cap provided zero protection); and it never descended into `@media`/`@supports` blocks, since `CSSMediaRule` has no `.style` of its own — only nested `.cssRules` — so any custom property defined inside a `prefers-color-scheme: dark` block (a common real pattern) was silently invisible. Fixed with a rule-count cap and recursive descent into grouping rules, both proven with synthetic CSSOM mocks since this code only runs in a real page context.
- Storage hygiene had never been audited: `tabState` (in-memory) was never cleared on `chrome.tabs.onRemoved`, only on same-tab navigation; `scan:<origin>` entries in `chrome.storage.local` had no cap or expiration at all — fine for casual use, a real problem for the extended professional use this tool is actually meant for (scanning many targets across an engagement, eventually hitting the storage quota with zero warning); and the main scan-result write had no error handling, so a quota failure would have silently broken the scan with no indication to the user. Fixed with a tab-close listener, a throttled (once/hour) cleanup pass that evicts oldest-scanned entries past a 500-entry cap and prunes expired NVD cache entries, and a try/catch around the write that degrades the badge color rather than failing silently — all verified against a mocked `chrome.storage.local` since this can't be exercised without a real extension runtime.
- A permanent regression test for `checkWordPressReadme`'s negative control accidentally contained the literal word "WordPress" inside text meant to simulate an unrelated page ("...nothing to do with WordPress") — which is exactly the condition the function correctly checks for, so the test failed for a reason that had nothing to do with the code being wrong. A quick standalone manual check earlier had used "WP" (abbreviated) and passed; the permanent version transcribed it differently. Caught immediately by actually running the suite rather than assuming a test that "should obviously pass" does.
- The custom rule editor (`options/options.html`/`options.js`) was built when the matcher supported 7 signal types. Three more (`requestUrl`, `cssVars`, `cspDomains`) were added to the engine in later sessions and never retrofitted into the editor form — meaning anyone using the UI (as opposed to hand-writing JSON) could never actually create a rule using WebSocket detection, CSS-framework fingerprinting, or CSP corroboration, despite the engine fully supporting all three. Found by directly checking whether the UI even mentioned those signal names, rather than assuming feature parity just because the engine had it. Fixed by adding matching fieldsets and wiring them through `buildSignalsFromForm`/`populateForm`/`findInvalidRegexes`/`signalSummary`, verified with a mocked-DOM round-trip test (save → re-open for editing → fields repopulate correctly) rather than just confirming the form renders.
- **Version-conflict detection.** When two signals for the same technology extracted genuinely different version strings, `evaluate()` silently kept only whichever had the highest confidence, discarding the disagreement entirely. A real example found while testing this: a stale CDN-cached script filename (`wp-emoji-release.min.js?ver=6.3.1`, confidence 70) outranked a more current live meta generator tag (`WordPress 6.5.0`, confidence 60) — the tool would have confidently reported the *older, wrong* version with no indication two signals disagreed. Fixed with a `versionsConflict()` comparator (segment-by-segment, not naive string-prefix — "1.2" vs "1.25" must count as a conflict even though "1.2" is a literal string-prefix of "1.25") that distinguishes real disagreement from signals simply differing in precision ("6.4" vs "6.4.2" is not a conflict). Findings now carry `versionConflict`/`allVersionsFound`, surfaced with a ⚠ indicator in the popup and included in both exports — the highest-confidence version is still shown as primary, but the disagreement is no longer hidden.
- **Implied-technology confidence picked whichever implicator happened to appear first in the ruleset array, not whichever had the strongest evidence.** PHP is implied by 8 different technologies in the real ruleset (WordPress, Laravel, MODX, Statamic, Pantheon, 1C-Bitrix, Adminer, Aegea) spanning very different confidence levels — under the old logic, if a weak niche detection (e.g. Aegea, confidence 70) happened to sit earlier in array order than a near-certain one (e.g. WordPress, often confidence 100), the weak one would silently set PHP's inferred confidence instead. Fixed by collecting every candidate implicator for a given target first, then picking the highest-confidence one — proved with a synthetic ruleset that deliberately places the weak implicator first and the strong one second, isolating array-order from confidence-order so the fix couldn't be confirmed by coincidence.
- `CWS_SUBMISSION.md` had gone stale relative to the actual code twice over: the `webRequest` justification only mentioned XHR/fetch, with no reference to WebSocket capture (added several sessions earlier for real-time framework detection); and the `host_permissions` / data-usage sections only listed the original 3 exposure-check paths (`.git`, `.env`, source maps), missing the 5 added later (`package.json`, `composer.lock`, `Gemfile.lock`, `requirements.txt`, `readme.html`). Found by checking file modification times against the submission doc's, rather than assuming a compliance document stays accurate on its own as the code around it keeps changing. Fixed, and added a lightweight content-check regression test so this specific class of drift gets caught by the suite going forward instead of requiring another manual audit to notice.
- Vulnerability lookup only ever checked the *winning* (highest-confidence) version once version-conflict detection existed — meaning a CVE that genuinely applies to the disagreeing, lower-confidence version could be silently missed. Concretely: a scriptSrc filename reporting `jquery-1.12.4.min.js` (real, CVE-affected) alongside a live global reporting `jQuery.fn.jquery = "3.6.0"` (higher confidence, not affected, so it wins as the *displayed* version) would have shown zero CVEs despite genuinely vulnerable evidence being present. Fixed by checking every distinct version found during a conflict, deduped by CVE id, rather than only the one chosen for display — verified with a test using jQuery's real CVE entries specifically because it lets the fix be proven against actual vulnerability data instead of a synthetic placeholder.
- The live NVD lookup's `keywordSearch` is fuzzy free-text matching, not exact — a query for "Bootstrap 3.4.1" could surface a CVE with nothing to do with the Bootstrap CSS framework but that happens to share the word "Bootstrap" with an unrelated advisory (proved with a constructed embedded-firmware example). NVD's API does support exact CPE-based matching, which would be strictly more precise — deliberately not implemented, because verifying CPE strings and matching behavior actually work requires hitting the real live API, and this environment has no network access to confirm that safely. Shipping unverified live-API code would break the same "don't guess, test it" rule this project has held everywhere else. What shipped instead: a coarse but fully offline-testable post-filter that discards any result whose description doesn't mention the technology name at all — and critically, the filtered count is surfaced in the UI (`filteredCount`), not silently dropped, so a filter that's wrong in some future edge case is at least visible rather than invisible.
- That same relevance filter immediately had a failure mode in the opposite, more dangerous direction: requiring the *exact full phrase* to appear meant multi-word product names in this ruleset ("New Relic Browser", "ASP.NET Core (Kestrel)") would have their genuinely relevant CVEs silently discarded, since a real advisory says "a vulnerability in New Relic agent," never the full marketing-style label verbatim. Proved this immediately after shipping the first version, by testing the filter from the other direction instead of assuming a good idea in one direction couldn't cause harm in another. For a security tool, a false negative — hiding a real vulnerability — is worse than the false positive the filter was built to catch. Fixed with a two-pass check: exact phrase first (strongest signal when it hits), falling back to matching any individual significant word (4+ characters) from the tech name only when the full phrase never appears — verified against all four cases at once (the original false positive, the new false negative, a parenthetical-qualified name, and a genuinely irrelevant multi-word case) so the fix couldn't have quietly broken what it was built to preserve.
- The significant-word fallback from the previous fix used plain substring matching (`.includes()`), which has its own real failure mode: "react" (from the tech name "React") is a substring of "reactor" and "reaction," so a completely unrelated industrial-control-systems CVE mentioning a "chemical reactor" and an "adverse reaction" would have false-matched as relevant to the React JavaScript framework. Found by testing this same function a third time from yet another angle rather than assuming two successful rounds of fixes meant it was now safe. Fixed by switching both the full-phrase check and the significant-word fallback to proper word-boundary regex matching instead of substring checks, with technology names correctly escaped first (so a literal "." in "Cal.com" isn't misinterpreted as a regex wildcard once matching moved from `.includes()` to a constructed `RegExp` — checked explicitly, since that's exactly the kind of thing a naive escape-less regex construction gets wrong). Verified five scenarios together in one pass: the reactor/reaction false positive, a genuine word-boundary React CVE, the original Bootstrap fix, the New Relic multi-word fix, and the Cal.com escaping case — specifically so a fourth fix to this function couldn't silently re-break any of the first three.
- The `\b`-based word-boundary fix from the previous round had its own bug, caught by testing it empirically rather than trusting the reasoning that produced it: `\b` is defined purely by transitions between word and non-word characters, which breaks for technology names *ending* in punctuation. "ASP.NET Core (Kestrel)" ends in `)`, and a trailing `\b` right after that closing paren fails to match even when the description contains the exact phrase verbatim — confirmed with a direct Node one-liner before writing the fix, not assumed from regex theory. This had been silently masked through two rounds of testing already, because the significant-word fallback ("kestrel" alone) still caught the case — meaning the primary full-phrase path was broken the whole time and nothing surfaced it until a test was written that called `isRelevantResult` directly instead of only exercising it through the full `queryLiveCves` round-trip, which let the fallback quietly cover for the bug. Fixed by switching from `\b` to lookaround assertions (`(?<![a-z0-9])...(?![a-z0-9])`), which check "not glued to an adjacent alphanumeric character" directly rather than relying on `\b`'s word-transition semantics that get inconsistent at punctuation boundaries. Verified Node's and Chrome's minimum-version lookbehind support before shipping it (Node 22 and Chrome 116+, this project's declared minimum, both fully support it since well before either baseline) rather than assuming a newer regex feature would just work. This is the fourth fix to this one function in two turns — worth naming plainly rather than glossing over, since it's a real signal that a small, sharp-edged piece of logic (string-to-regex construction with user-controlled-ish input) warranted more upfront scrutiny than it got on the first pass, not evidence the process failed. Each bug was still caught before shipping, by continuing to test the fix instead of stopping once tests passed.
- A fifth issue, this time in the threshold rather than the matching mechanism: the 4-character significant-word cutoff made the fallback path completely unreachable for "Vue.js" (splits to "vue"/3 chars and "js"/2 chars, both under the cutoff), so a genuine CVE saying just "Vue" — the overwhelmingly common way advisories reference it — would have been silently dropped. Checked the whole ruleset's names before picking a fix, rather than guessing at a new threshold number: dropping the cutoff to 3 characters blanket-wide would have newly allowed words like "web," "com," "net," "egg," "ant," "amp," "one," "new," "dev," "bot" as fallback matches — reintroducing real false-positive risk across many unrelated entries, the exact class of bug fixed twice already in this same function. Fixed with a small, deliberately curated allowlist (just `vue` for now, added one word at a time and only when concretely justified) instead of a threshold change, and specifically verified the four near-identical rejected cases (Cal.com/Fly.io/PDF.js/Act-On, each with an equally short but far more generic or common-English-word core token) stayed correctly strict — proving the allowlist didn't quietly become a blanket rule that would have undone the false-positive fixes from the third round.
- Applying the same substring-vs-word-boundary scrutiny to a different piece of code turned up a real bug in `security-headers.js`: `parseSetCookieFlags` checked the entire raw `Set-Cookie` string — cookie name and value included, not just the attribute list — for the substring `"secure"`. A cookie literally named `insecure_debug_flag` matches `"secure"` as a substring of `"insecure"`, so it was reported as having the Secure attribute set when it genuinely didn't — silently inflating a site's header grade. The first test written for this ("cookie missing Secure/HttpOnly/SameSite is flagged weak") didn't catch it, because that cookie was ALSO missing HttpOnly and SameSite, so the overall "weak" verdict was accidentally still correct despite the underlying `secure: true` being wrong — the bug was only exposed by constructing a cookie where Secure was the *only* thing missing, isolating exactly which flag the false positive affected. Fixed by splitting the raw header on `;` and only checking the attribute segments (never the name=value pair) for an exact case-insensitive token match rather than a substring search anywhere in the whole string — same underlying fix shape as the CVE relevance filter, applied here because it's the same bug class, not a coincidence.
- A deliberate sweep of every `.includes()` and dynamically-constructed `RegExp` in the production codebase, prompted by finding the same substring-matching bug twice, turned up no third instance of *that* specific bug class — but did surface a different, real vulnerability class that had never been checked for anywhere in this project: CSV/formula injection (CWE-1236). ISA's popup CSV export includes technology `version` values, and 13 technologies (jQuery, React, Vue.js, Sentry, and 10 more) read their version directly from a live JS global with zero content restriction — no regex, no digit-only capture group, just whatever string the page's own JavaScript object happens to contain. A page under attacker control (a directly relevant threat model for a tool whose users scan potentially malicious or compromised sites) could set e.g. `window.jQuery.fn.jquery` to a string starting with `=`, which Excel/Sheets interprets as a formula on open — standard CSV quote-escaping protects the CSV's own structure, not spreadsheet formula interpretation, which is a different concern entirely. Verified the attack surface was real (checked the ruleset for how many technologies actually have this exposure) before treating it as a finding, then fixed with the standard OWASP mitigation — a leading single quote on any field starting with `=`, `+`, `-`, `@`, tab, or carriage return — applied to the popup's per-finding export where it's confirmed exploitable, and to the history page's summary export too, where it isn't currently exploitable (every field there is structurally constrained: a URL origin always begins with a scheme, grades are ISA's own single-letter computation) but is protected anyway for consistency and in case that export's schema ever grows a field with less rigid structure.
