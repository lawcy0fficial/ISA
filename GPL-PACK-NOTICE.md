# GPL-3.0 extended technology pack — read before enabling or redistributing

`lib/technologies-gpl-extended.json` is **not** part of ISA's MIT-licensed
core. It's a separate, optional file containing technology fingerprints
converted from [webappanalyzer](https://github.com/enthec/webappanalyzer),
a community-maintained continuation of Wappalyzer's original dataset,
**licensed GPL-3.0-only**.

## What this means practically

- **ISA's own code (everything except this one file) stays MIT**, regardless of whether you enable this pack.
- The pack is **disabled by default** — `background.js` only loads and merges it if you explicitly turn it on in the options page (`isa_enable_gpl_pack` in `chrome.storage.local`).
- **If you enable it and then redistribute your copy of ISA** (share the extension, publish it, ship it to others) **with the pack turned on or bundled**, GPL-3.0's copyleft terms apply to at least this data file: recipients must be able to get the source, and any modifications to this file must stay GPL-3.0.
- **If you only ever use it locally yourself** and never redistribute, GPL-3.0's distribution obligations don't practically engage — GPL conditions attach to *distribution*, not private use.
- **This project has not been reviewed by a lawyer.** If you're planning to actually ship ISA (Chrome Web Store, a client engagement deliverable, anything leaving your own machine) with this pack enabled, get real legal review before you do — this notice is a plain-language flag, not legal advice.

## What's not done yet

Proper GPL-3.0 compliance for redistribution normally means including the
full license text alongside the code. That's not bundled in this repo yet
— add the canonical text from
[gnu.org/licenses/gpl-3.0.txt](https://www.gnu.org/licenses/gpl-3.0.txt)
before actually shipping this pack to anyone.

## Where the data came from

Entries in `lib/technologies-gpl-extended.json` were hand-converted (not
mechanically copy-pasted) into ISA's own signal schema — named categories
instead of numeric IDs, separate `version`/`confidence` fields instead of
inline pattern tags, and ISA's simpler DOM-selector model instead of
webappanalyzer's richer multi-condition DOM checks. Sourced from two real
fetches of the underlying dataset: webappanalyzer's own `src/technologies/p.json`,
and a combined-file mirror (`iiiusky/WappalyzerParse/technologies.json`)
that includes the full category-ID table, which is what made the second,
larger conversion batch (1C-Bitrix through Aircall) possible with accurate
category names instead of guessed ones. Each entry keeps `"verified": false`
since none of these have been independently re-confirmed against a live
target by ISA's maintainer — same convention as every other unverified
entry in the core ruleset. Entries were skipped, not guessed, wherever the
source data was ambiguous or looked like a possible transcription error in
the mirror (e.g. an oddly-shaped cookie-signal entry) rather than convert
something uncertain.

## Extending this pack further

The full webappanalyzer dataset has thousands more entries across
`src/technologies/a.json` through `z.json`. The same conversion pattern
used for the 29 entries currently in this file can be repeated for any of
them — categorize by the technology's actual function, translate each
signal type into ISA's schema, mark `verified: false`, and run both
`node tools/lint-rules.mjs`
and `node tests/run.mjs` before considering it done, exactly like every
other addition to this project.
