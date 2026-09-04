// Same-origin here means scheme + exact hostname + port, per the roadmap's
// authorization-boundary reasoning: an operator attested for the URLs they
// submitted, not for every subdomain or port a crawler happens to find.
function isSameOrigin(candidate: URL, origin: URL): boolean {
  return candidate.protocol === origin.protocol && candidate.hostname === origin.hostname && candidate.port === origin.port;
}

const HREF_PATTERN = /<a\b[^>]*\bhref\s*=\s*["']([^"']*)["']/gi;
const FORM_ACTION_PATTERN = /<form\b[^>]*\baction\s*=\s*["']([^"']*)["']/gi;

// Pure, no I/O: takes a page's already-fetched HTML and its URL, and returns the
// same-origin `<a href>`/`<form action>` links found in it, resolved to absolute
// URLs and deduped. No robots.txt filtering yet (that's 015).
export function discoverLinks(page: { url: URL; html: string }): string[] {
  const found = new Set<string>();

  for (const pattern of [HREF_PATTERN, FORM_ACTION_PATTERN]) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(page.html)) !== null) {
      const raw = match[1];
      if (raw === undefined || raw === '') continue;

      let resolved: URL;
      try {
        resolved = new URL(raw, page.url);
      } catch {
        continue;
      }
      if (!isSameOrigin(resolved, page.url)) continue;

      resolved.hash = '';
      found.add(resolved.toString());
    }
  }

  return Array.from(found);
}
