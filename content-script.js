/**
 * ISA content script — runs in the isolated world.
 * Collects passive, already-rendered page evidence and hands it to the
 * background service worker. Does not read cross-origin data beyond what
 * the page itself exposes to the DOM.
 */
(function () {
  function collectMeta() {
    return Array.from(document.querySelectorAll('meta[name]')).map(m => ({
      name: m.getAttribute('name') || '',
      content: m.getAttribute('content') || ''
    }));
  }

  function collectScriptSrcs() {
    return Array.from(document.querySelectorAll('script[src]'))
      .map(s => s.getAttribute('src'))
      .filter(Boolean)
      .slice(0, 400);
  }

  function collectInlineScriptSample() {
    // Concatenate a bounded sample of inline script text — enough to catch
    // version comments / webpack markers without hauling huge bundles around.
    const inline = Array.from(document.querySelectorAll('script:not([src])'))
      .map(s => s.textContent || '')
      .join('\n');
    return inline.slice(0, 20000);
  }

  function collectHtmlSample() {
    // Comments + head HTML + a slice of body HTML — bounded for performance.
    const headHtml = document.head ? document.head.innerHTML : '';
    const bodyHtml = document.body ? document.body.innerHTML.slice(0, 15000) : '';
    return (headHtml + '\n' + bodyHtml).slice(0, 30000);
  }

  function collectDomSignals() {
    // matchedSelectors is intentionally left empty here — background.js's
    // enrichDomSelectors() checks the ruleset's actual dom.selector values
    // live via chrome.scripting.executeScript instead of a hand-maintained
    // watchlist in this file, which is exactly what let DOM-based detection
    // for several technologies (React, Vue, hCaptcha, PWA, and others)
    // silently go stale every time a new dom-signal entry was added to the
    // ruleset without this list being updated to match. This function still
    // owns the ng-version attribute extraction, a different mechanism
    // (attribute value capture, not selector presence) that doesn't have
    // the same staleness problem since Angular is its only consumer.
    const attrs = [];
    const ngHost = document.querySelector('[ng-version]');
    if (ngHost) attrs.push({ attr: 'ng-version', value: ngHost.getAttribute('ng-version') || '' });
    return { matchedSelectors: [], attrs };
  }

  function collectFaviconUrl() {
    const link = document.querySelector('link[rel~="icon"]');
    if (link && link.href) return link.href;
    try { return new URL('/favicon.ico', location.origin).href; } catch { return null; }
  }

  function collectCssCustomProperties() {
    // Modern component frameworks (Bootstrap 5+, Tailwind, Chakra UI, Ant
    // Design, Mantine, Radix, Shoelace, Ionic) deliberately namespace their
    // CSS custom properties to avoid collisions with consuming projects —
    // that same namespacing makes them an unusually reliable fingerprint,
    // since nobody's own stylesheet accidentally emits "--chakra-colors-blue-500".
    // Only same-origin stylesheets are readable; cross-origin ones throw on
    // .cssRules access and are silently skipped, same constraint the browser
    // itself imposes for any script, not something ISA can work around.
    const props = new Set();
    let rulesExamined = 0;
    const MAX_RULES = 20000; // bounds worst-case time on pathological stylesheets
    // regardless of how many distinct property names they contain — the
    // props.size cap alone doesn't help if property names never repeat.

    // CSSMediaRule/CSSSupportsRule/CSSContainerRule have no .style of their
    // own — their content lives one level deeper in .cssRules. A flat loop
    // that only checks rule.style silently misses everything inside e.g.
    // @media (prefers-color-scheme: dark) { :root { --bs-primary: ...; } },
    // a genuinely common place for frameworks to define custom properties.
    function visitRuleList(rules) {
      for (const rule of rules) {
        if (rulesExamined++ >= MAX_RULES || props.size >= 500) return false;
        if (rule.style) {
          for (let i = 0; i < rule.style.length; i++) {
            const prop = rule.style[i];
            if (prop && prop.startsWith('--')) props.add(prop);
          }
        } else if (rule.cssRules) {
          if (visitRuleList(rule.cssRules) === false) return false;
        }
      }
      return true;
    }

    try {
      for (const sheet of document.styleSheets) {
        let rules;
        try { rules = sheet.cssRules || sheet.rules; } catch { continue; }
        if (!rules) continue;
        if (visitRuleList(rules) === false) break;
      }
    } catch { /* ignore — best-effort collection */ }
    return [...props];
  }

  function collectSubresources() {
    // Passive supply-chain/transport signals, gathered from elements the
    // page already rendered — no extra network requests, so unlike
    // exposure-checks.js this runs on every automatic scan, not just on
    // an explicit opt-in button press.
    //
    // Two things fall out of the same element list: which cross-origin
    // scripts/stylesheets lack Subresource Integrity (a compromised or
    // MITM'd CDN could silently swap the file's contents with no
    // detection), and which resources load over plain http:// on an
    // https:// page (mixed content — actively blocked or degraded by
    // the browser itself, but still worth surfacing as a hygiene signal
    // since it usually means an unmaintained third-party embed).
    const pageIsHttps = location.protocol === 'https:';
    const els = document.querySelectorAll('script[src], link[rel="stylesheet"][href]');
    const out = [];
    for (const el of els) {
      const tag = el.tagName.toLowerCase();
      const raw = tag === 'script' ? el.getAttribute('src') : el.getAttribute('href');
      if (!raw) continue;
      let abs;
      try { abs = new URL(raw, location.href); } catch { continue; }
      // data:/blob: URLs have no meaningful integrity or mixed-content story.
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
      const integrityAttr = (el.getAttribute('integrity') || '').trim();
      out.push({
        tag,
        url: abs.href,
        crossOrigin: abs.origin !== location.origin,
        hasIntegrity: integrityAttr.length > 0,
        mixedContent: pageIsHttps && abs.protocol === 'http:'
      });
      if (out.length >= 300) break; // bounded, matches collectScriptSrcs' own cap
    }
    return out;
  }

  function collectAndSend() {
    const payload = {
      type: 'ISA_PAGE_EVIDENCE',
      url: location.href,
      origin: location.origin,
      cookiesRaw: document.cookie || '',
      metaTags: collectMeta(),
      scriptSrcs: collectScriptSrcs(),
      htmlSample: collectHtmlSample() + '\n' + collectInlineScriptSample(),
      dom: collectDomSignals(),
      faviconUrl: collectFaviconUrl(),
      cssVars: collectCssCustomProperties(),
      subresources: collectSubresources()
    };

    chrome.runtime.sendMessage(payload).catch(() => {
      // background may not be ready yet on very fast navigations; content
      // scripts can't retry a MessageChannel post, so this is best-effort.
    });
  }

  // Initial collection on page load.
  collectAndSend();

  // SPA route changes (history.pushState/replaceState) don't reload the
  // document, so this content script instance stays alive and doesn't
  // re-run automatically. background.js listens for
  // chrome.webNavigation.onHistoryStateUpdated and asks us to recollect —
  // that's the only reliable way to detect a virtual-URL change, since
  // popstate does NOT fire for pushState/replaceState calls the page makes
  // itself (only for user back/forward navigation).
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === 'ISA_REQUEST_RESCAN') collectAndSend();
  });
})();
