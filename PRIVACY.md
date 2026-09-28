# ISA Privacy Policy

_Last updated: 2026-09-17_

## Summary

ISA does not collect, transmit, sell, or share any user data. Everything it
reads about a page you visit stays on your device, stored locally by your
browser via `chrome.storage.local`. ISA has no backend server, makes no
network calls to any server operated by its developer, and does not use
analytics or tracking of any kind. Six opt-in features send narrow,
specific data to public (non-developer-operated) services when you
explicitly click them — NIST's NVD (twice over: a keyword-based lookup and
a separate, more precise CPE-based lookup for a small set of
technologies), CISA's KEV catalog, FIRST.org's EPSS, GitHub's public
security advisories API, and Google's OSV.dev — see "Where data goes"
below.

## What ISA reads, and why

To identify the technologies a website uses, ISA reads:

- **HTTP response headers** of the page you're viewing (e.g. `Server`,
  `X-Powered-By`, security headers) — to identify server software and grade
  security header hygiene.
- **Cookie names** (not values) for the current site, including HttpOnly
  cookies — certain cookie-naming patterns are reliable indicators of what
  a site is built with (e.g. `laravel_session`).
- **Page content** already rendered in your browser: meta tags, script
  paths, inline script text, comments, DOM structure — read the same way
  the page itself is already visible to you.
- **A small, fixed set of live JavaScript values** the page itself sets
  (e.g. `React.version`, `jQuery.fn.jquery`) — read via a page-context
  probe, since these aren't visible from a content script's isolated
  world.
- **XHR/fetch request URLs** made by the page — to detect API-based
  integrations that never appear in visible page content.
- **The page's favicon**, hashed locally (SHA-256) — to compare against a
  local table of known tool default-install favicons.

## Optional, explicit-action-only checks

ISA includes an opt-in "exposure checks" feature that, only when you click
a button to run it, makes read-only requests to `/.git/HEAD`, `/.git/config`,
`/.env`, `/package.json`, `/composer.lock`, `/Gemfile.lock`,
`/requirements.txt`, `/readme.html`, any exposed JavaScript source maps,
a randomly-named nonexistent path (to check for verbose debug/error pages
left on in production), a handful of common static-asset directories (to
check for open directory listings), `/.well-known/security.txt` and
`/security.txt` (RFC 9116 vulnerability-disclosure contact), and
`/robots.txt`/any `Sitemap:` URLs it declares — all on the site you're
currently viewing, to check whether these are unintentionally publicly
accessible or disclose more than intended. This never runs automatically.
When checking `.env` exposure, ISA reports only the *names* of keys found,
never their values. Dependency manifests (`package.json` and friends) are
different — if exposed, they're meant to be a plain declaration of
dependency names and versions with no secrets in them, so those version
strings are reported in full, since that's the entire point of that check.

A separate opt-in "check GraphQL introspection" button sends a standard,
read-only GraphQL introspection query (the same query any GraphQL IDE
tool sends automatically) as a POST request to a handful of conventional
GraphQL endpoint paths on the site you're viewing, to check whether schema
introspection is left enabled in production. It's a separate button from
the other exposure checks specifically because it's a POST rather than a
GET, and only against paths that may or may not exist.

ISA also includes an opt-in "check live CVEs" button per detected
technology. Only when clicked, it sends the detected technology name and
version string (nothing else — not the page, not any target data) to
NIST's public National Vulnerability Database API (`services.nvd.nist.gov`)
to retrieve current CVE records, since ISA's local vulnerability table is
static and can go stale. Results are cached locally for 12 hours to avoid
repeat queries. ISA never fetches, stores, or displays exploit code or
proof-of-concept content —
only CVE IDs, descriptions, and CVSS scores from NVD, plus deep links to
NVD/MITRE/Exploit-DB/GitHub Advisories so you can look up whatever's
already publicly indexed on those platforms yourself.

For a small, specifically-verified set of technologies (currently jQuery,
jQuery UI, Bootstrap, Lodash, Moment.js, and WordPress — see
`lib/cpe-lookup.js` for the exact list), a second, separate opt-in button
("check precise CVE match (CPE, experimental)") sends the same technology
name and version to the same NIST NVD API, but using an exact CPE-based
match instead of the fuzzy keyword search the first button uses — this
can avoid false positives where a keyword search surfaces an unrelated
advisory that happens to share a word. Marked "experimental" in the popup
itself because, unlike every other network-calling feature in ISA, its
live behavior against NVD's real API has not been personally end-to-end
verified by whoever last updated this policy — see the code comments in
`lib/cpe-lookup.js` for the full explanation. It sends nothing different
in kind from the first NVD button: only a technology name and version
string.

ISA also includes an opt-in "check OSV.dev" button per detected,
versioned technology that ISA has a verified package-registry mapping
for (currently 27 technologies — see `lib/osv-lookup.js`). Only when
clicked, it sends the technology's package name, registry ecosystem
(e.g. "npm"), and detected version — nothing else — to Google's OSV.dev
API (`api.osv.dev/v1/query`) to check for vulnerabilities aggregated from
GHSA, PyPA, RustSec, and other open-source vulnerability databases. This
is a different question from the CVE-based checks above: rather than
confirming a CVE ISA already found, it can surface a vulnerability for a
technology ISA detected but has no local vuln-db.json entry for at all.
OSV.dev states its API is not currently rate-limited and requires no API
key.

ISA also includes an opt-in "confirm exploitation status (CISA KEV +
EPSS + GHSA)" button, shown for any finding where the local vulnerability
table matched a CVE. Only when clicked, it sends the matched CVE ID
string(s) — nothing else, not the page, not any target data — to three
public feeds: CISA's Known Exploited Vulnerabilities catalog
(`cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
the US government's list of CVEs confirmed to be actively exploited),
FIRST.org's EPSS API (`api.first.org/data/v1/epss`, a public exploit-
prediction score), and GitHub's public security advisories API
(`api.github.com/advisories`, a third, independently-curated advisory
source covering npm/pip/etc. package ecosystems). The full KEV catalog is
cached locally for 6 hours after first fetch to avoid re-downloading it on
every click. Like the NVD lookup, this only ever sends CVE ID strings ISA
already found — never anything about the page, the user, or the site
being scanned — and never runs anything against the target; it is
read-only cross-referencing against three public feeds.

## "Scan all tabs"

The popup's "scan all tabs" button reloads any currently-open http(s) tab
whose origin ISA has not already scanned in this session — it never
reloads a tab that already has stored results, and it reloads at most one
tab per unscanned origin, not every tab open on the same site. This
triggers ISA's normal per-page scan for those tabs, exactly as if you'd
reloaded each one yourself; it does not send anything anywhere beyond
what a normal scan already does, and it never touches a tab outside your
own open windows.

ISA also includes an opt-in "extended technology pack" (in the options
page) that adds a small set of additional technology fingerprints. This is
a **licensing** consideration, not a privacy one — enabling it doesn't
transmit any new data anywhere, it just loads an additional local JSON
file bundled in the extension. See `GPL-PACK-NOTICE.md` for what enabling
and/or redistributing it actually means.

## Where data goes

Nowhere but your own browser, with one narrow exception. Scan results,
security grades, exposure findings, and any custom fingerprint rules you
define are stored in `chrome.storage.local`, local to your browser
profile, and never transmitted anywhere. Exports (JSON/CSV/Markdown/SARIF) are
written only to your own device when you explicitly click an export
button, via Chrome's standard downloads mechanism.

The exceptions: clicking "check live CVEs" or "check precise CVE match
(CPE, experimental)" on a specific finding sends that technology's name
and version string to NIST's public NVD API (services.nvd.nist.gov);
clicking "check OSV.dev" sends a package name, ecosystem, and version to
Google's OSV.dev API (api.osv.dev); clicking "confirm exploitation
status" sends matched CVE ID strings to CISA's public KEV feed
(cisa.gov), FIRST.org's public EPSS API (api.first.org), and GitHub's
public advisories API (api.github.com) — see "Optional,
explicit-action-only checks" above. Nothing else in ISA transmits data
anywhere.

## Third parties

ISA's own logic makes no calls to any server operated by ISA's developer.
The outbound requests described above go to NIST's NVD (queried two
different ways, by the same underlying API), CISA's KEV catalog,
FIRST.org's EPSS API, GitHub's public advisories API, and Google's
OSV.dev — a US government database, a US government agency's public
feed, a nonprofit vulnerability-scoring standards body, GitHub's own
public security advisory database, and Google's open-source
vulnerability aggregator, respectively, none of them third-party vendors
in the data-sharing sense — solely to look up public CVE/exploitation
data for a technology name, version, package identifier, or CVE ID. No
other third party receives any data from ISA.


ISA does not share data with any third party because it does not transmit
data anywhere in the first place. It does not use any third-party
analytics, advertising, or tracking SDKs.

## Changes to this policy

If this policy changes, the "Last updated" date above will change and the
updated text will ship with the next version of the extension.

## Contact

For questions about this policy, open an issue on the project's source
repository.
