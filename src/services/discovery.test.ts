import { describe, expect, it } from 'vitest';
import { discoverLinks } from './discovery.js';

describe('discoverLinks', () => {
  it('returns same-origin links found in anchor hrefs and form actions, resolved to absolute URLs', () => {
    const html = `
      <a href="/about">About</a>
      <form action="/contact"></form>
    `;
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null);

    expect(links.sort()).toEqual(['https://example.com/about', 'https://example.com/contact']);
  });

  it('excludes cross-origin, different-port, and different-scheme links', () => {
    const html = `
      <a href="https://evil.example/steal">Cross-origin</a>
      <a href="https://example.com:8443/admin">Different port</a>
      <a href="http://example.com/insecure">Different scheme</a>
      <a href="/same-origin">Same origin</a>
    `;
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null);

    expect(links).toEqual(['https://example.com/same-origin']);
  });

  it('dedupes repeated links to the same URL', () => {
    const html = `
      <a href="/about">About</a>
      <a href="/about">About again</a>
      <form action="/about"></form>
    `;
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null);

    expect(links).toEqual(['https://example.com/about']);
  });
});

describe('discoverLinks robots.txt filtering', () => {
  it('excludes links whose path matches a Disallow rule', () => {
    const html = `
      <a href="/admin/settings">Admin</a>
      <a href="/contact">Contact</a>
    `;
    const robotsTxt = 'User-agent: *\nDisallow: /admin\n';
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, robotsTxt);

    expect(links).toEqual(['https://example.com/contact']);
  });

  it('applies a Disallow rule only to the host whose robots.txt it came from', () => {
    // A robots.txt speaks for its own origin. Once the crawl may cross to another
    // in-scope host (038), applying this page's rules to that host's paths blocks
    // URLs nobody disallowed — and says nothing about the ones that host does
    // disallow. The cross-host candidate is returned here and gated against its
    // own robots.txt by the caller, which is the only place that can fetch it.
    const html = `
      <a href="/admin/settings">Own admin</a>
      <a href="https://api.example.com/admin/settings">Another host's admin</a>
    `;
    const robotsTxt = 'User-agent: *\nDisallow: /admin\n';
    const scope = { in: ['example.com'], out: [] };
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, robotsTxt, scope);

    expect(links).toEqual(['https://api.example.com/admin/settings']);
  });
});

describe('discoverLinks program scope', () => {
  const scope = { in: ['example.com'], out: ['secret.example.com'] };

  it('follows a link to another in-scope host', () => {
    const html = '<a href="https://blog.example.com/post">Blog</a>';
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null, scope);

    expect(links).toEqual(['https://blog.example.com/post']);
  });

  it('does not follow links to out-of-scope or unscoped hosts', () => {
    const html = `
      <a href="https://secret.example.com/x">Excluded</a>
      <a href="https://evil.example/steal">Unscoped</a>
      <a href="/about">Same host</a>
    `;
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null, scope);

    expect(links).toEqual(['https://example.com/about']);
  });

  it('reports every off-host link hostname so the inventory can record them', () => {
    const html = `
      <a href="https://blog.example.com/post">Blog</a>
      <a href="https://evil.example/steal">Unscoped</a>
      <a href="https://blog.example.com/other">Blog again</a>
      <a href="/about">Same host</a>
    `;
    const { hostnames } = discoverLinks({ url: new URL('https://example.com/'), html }, null, scope);

    expect(hostnames.sort()).toEqual(['blog.example.com', 'evil.example']);
  });

  it('follows an in-scope host on another port, the same as any other in-scope host', () => {
    // Scope is attested per host, not per port: an operator who put
    // `example.com` in scope authorized the host, and the origin's own port is
    // not a narrower boundary than a sibling host's.
    const html = '<a href="https://example.com:8443/admin">Same host, other port</a>';
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null, scope);
    expect(links).toEqual(['https://example.com:8443/admin']);
  });

  it('keeps the same-origin rule when no scope is given', () => {
    const html = '<a href="https://blog.example.com/post">Blog</a>';
    const { links } = discoverLinks({ url: new URL('https://example.com/'), html }, null);

    expect(links).toEqual([]);
  });
});
