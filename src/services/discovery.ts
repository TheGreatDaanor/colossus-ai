import { classifyHost, type Scope } from './programs.js';

// Same-origin here means scheme + exact hostname + port, per the roadmap's
// authorization-boundary reasoning: an operator attested for the URLs they
// submitted, not for every subdomain or port a crawler happens to find.
function isSameOrigin(candidate: URL, origin: URL): boolean {
  return candidate.protocol === origin.protocol && candidate.hostname === origin.hostname && candidate.port === origin.port;
}

// Inside a program, the authorization boundary is the program's scope, not the
// page's origin: an operator who put `example.com` in scope authorized every
// host under it, including ones no certificate ever named. Without a program
// there is no such attestation, so the same-origin rule still holds.
//
// Scope is attested per host, so the port is not part of the test — including
// for the origin's own host. Singling that one host out for a same-origin check
// would make the page's own admin port the one in-scope address the crawl
// refused to follow, which is not a boundary anyone drew.
function mayFollow(candidate: URL, origin: URL, scope: Scope | null): boolean {
  if (scope === null) return isSameOrigin(candidate, origin);
  if (candidate.protocol !== 'https:' && candidate.protocol !== 'http:') return false;
  return classifyHost(candidate.hostname, scope) === 'in_scope';
}

const HREF_PATTERN = /<a\b[^>]*\bhref\s*=\s*["']([^"']*)["']/gi;
const FORM_ACTION_PATTERN = /<form\b[^>]*\baction\s*=\s*["']([^"']*)["']/gi;

// Only `Disallow` is honoured — `Allow`, crawl-delay and sitemap directives are
// deliberately out of scope for this phase.
// Exported because a scoped crawl reaches hosts whose robots.txt the caller must
// fetch itself: only it can do I/O, and only that host's own rules govern it.
export function disallowedPrefixes(robotsTxt: string | null): string[] {
  if (robotsTxt === null) return [];

  const prefixes: string[] = [];
  for (const line of robotsTxt.split(/\r?\n/)) {
    const withoutComment = line.split('#')[0] ?? '';
    const match = /^\s*disallow\s*:\s*(\S*)\s*$/i.exec(withoutComment);
    if (match === null) continue;

    // `Disallow:` with an empty value means "nothing is disallowed" — not a
    // prefix that matches every path.
    const prefix = match[1] ?? '';
    if (prefix === '') continue;

    prefixes.push(prefix);
  }

  return prefixes;
}

// What one page's links yielded: the URLs the crawl may fetch, and every other
// host those links named. The hostnames are reported whether or not they are
// followable — an unscoped host is exactly what an operator needs to see in
// order to widen scope deliberately.
export type DiscoveredLinks = { links: string[]; hostnames: string[] };

// Pure, no I/O: takes a page's already-fetched HTML and its URL, and returns the
// followable `<a href>`/`<form action>` links found in it, resolved to absolute
// URLs and deduped, minus anything the target's robots.txt disallows. With a
// program `scope`, followable means in-scope rather than same-origin.
export function discoverLinks(
  page: { url: URL; html: string },
  robotsTxt: string | null,
  scope: Scope | null = null,
): DiscoveredLinks {
  const disallowed = disallowedPrefixes(robotsTxt);
  const found = new Set<string>();
  const hostnames = new Set<string>();

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
      if (resolved.hostname !== '' && resolved.hostname !== page.url.hostname) hostnames.add(resolved.hostname);
      if (!mayFollow(resolved, page.url, scope)) continue;
      // A robots.txt speaks only for the origin it was served from. Now that a
      // scoped crawl may cross hosts, applying this page's rules to another
      // host's paths would block URLs nobody disallowed while still saying
      // nothing about the ones that host does disallow. A cross-host candidate
      // is returned and gated against its own robots.txt by the caller, which
      // is the only place that can fetch it.
      const ownHost = resolved.hostname === page.url.hostname;
      if (ownHost && disallowed.some((prefix) => resolved.pathname.startsWith(prefix))) continue;

      resolved.hash = '';
      found.add(resolved.toString());
    }
  }

  return { links: Array.from(found), hostnames: Array.from(hostnames) };
}
