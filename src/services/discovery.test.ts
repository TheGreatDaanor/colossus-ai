import { describe, expect, it } from 'vitest';
import { discoverLinks } from './discovery.js';

describe('discoverLinks', () => {
  it('returns same-origin links found in anchor hrefs and form actions, resolved to absolute URLs', () => {
    const html = `
      <a href="/about">About</a>
      <form action="/contact"></form>
    `;
    const links = discoverLinks({ url: new URL('https://example.com/'), html }, null);

    expect(links.sort()).toEqual(['https://example.com/about', 'https://example.com/contact']);
  });

  it('excludes cross-origin, different-port, and different-scheme links', () => {
    const html = `
      <a href="https://evil.example/steal">Cross-origin</a>
      <a href="https://example.com:8443/admin">Different port</a>
      <a href="http://example.com/insecure">Different scheme</a>
      <a href="/same-origin">Same origin</a>
    `;
    const links = discoverLinks({ url: new URL('https://example.com/'), html }, null);

    expect(links).toEqual(['https://example.com/same-origin']);
  });

  it('dedupes repeated links to the same URL', () => {
    const html = `
      <a href="/about">About</a>
      <a href="/about">About again</a>
      <form action="/about"></form>
    `;
    const links = discoverLinks({ url: new URL('https://example.com/'), html }, null);

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
    const links = discoverLinks({ url: new URL('https://example.com/'), html }, robotsTxt);

    expect(links).toEqual(['https://example.com/contact']);
  });
});
