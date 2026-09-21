import { describe, expect, it, vi } from 'vitest';
import { runAccessControlChecks, type HeaderedFetchImpl, type Identity } from './access-control.js';

// A fake HeaderedFetchImpl driven by a lookup keyed on (url, identifying header).
// The oracle only ever distinguishes identities by what their headers make the
// server return, so a fixture maps a header value to the body that identity sees;
// the empty (no-auth) identity is the `''` key.
function fakeFetch(table: Record<string, Record<string, { status: number; body: string }>>): HeaderedFetchImpl {
  return vi.fn(async (url, headers) => {
    const forUrl = table[url] ?? {};
    const key = headers['cookie'] ?? '';
    const response = forUrl[key] ?? { status: 404, body: '' };
    return response;
  });
}

describe('runAccessControlChecks', () => {
  it('fires idor when a peer receives the owner ground truth and no-auth diverges', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/1'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // Both signed-in users see Alice's invoice; a logged-out request is bounced to login.
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/1': {
        'session=alice': { status: 200, body: 'Invoice #1 — total $500' },
        'session=bob': { status: 200, body: 'Invoice #1 — total $500' },
        '': { status: 302, body: 'redirecting to /login' },
      },
    });

    const { outcomes } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(1);
    const [outcome] = outcomes;
    expect(outcome?.category).toBe('idor');
    expect(outcome?.url).toBe('https://app.test/invoice/1');
    expect(outcome?.ownerLabel).toBe('alice');
    expect(outcome?.unauthorizedLabel).toBe('bob');
    // The proof carries digests and statuses, never any body content.
    const serialized = JSON.stringify(outcome?.proof);
    expect(serialized).not.toContain('Invoice');
    expect(serialized).not.toContain('$500');
    expect(outcome?.proof.owner.digest).toBe(outcome?.proof.unauthorized.digest);
    expect(outcome?.proof.owner.digest).not.toBe(outcome?.proof.noAuth.digest);
  });

  it('records no finding for a public resource everyone sees identically', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/pricing'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // The same page for owner, peer, and no-auth — a public page, not a leak.
    const same = { status: 200, body: '<h1>Pricing</h1>' };
    const fetchImpl = fakeFetch({
      'https://app.test/pricing': { 'session=alice': same, 'session=bob': same, '': same },
    });

    const { outcomes } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(0);
  });

  it('records no finding when owner and peer share an error page the owner never had access to', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/999'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // The resource is gone: both signed-in users get the same 404, no-auth is bounced
    // to login. Digests match and no-auth diverges, but the owner never received a
    // private resource, so this is a shared error page, not an IDOR.
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/999': {
        'session=alice': { status: 404, body: 'Not found' },
        'session=bob': { status: 404, body: 'Not found' },
        '': { status: 302, body: 'redirecting to /login' },
      },
    });

    const { outcomes } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(0);
  });

  it('isolates a failing URL so other URLs still produce findings', async () => {
    const identities: Identity[] = [
      {
        label: 'alice',
        headers: { cookie: 'session=alice' },
        privateUrls: ['https://app.test/dead', 'https://app.test/invoice/1'],
      },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    const fetchImpl: HeaderedFetchImpl = vi.fn(async (url, headers) => {
      if (url === 'https://app.test/dead') throw new Error('connection refused');
      const cookie = headers['cookie'] ?? '';
      if (cookie === '') return { status: 302, body: 'login' };
      return { status: 200, body: 'Invoice #1' };
    });

    const { outcomes } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]?.url).toBe('https://app.test/invoice/1');
  });

  it('records no finding when the peer sees something different from the owner', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/1'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // Bob gets his own view, not Alice's — object-level auth is working.
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/1': {
        'session=alice': { status: 200, body: 'Invoice #1 — total $500' },
        'session=bob': { status: 403, body: 'forbidden' },
        '': { status: 302, body: 'redirecting to /login' },
      },
    });

    const { outcomes } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(0);
  });

  it('fires unauthenticated-resource-access when no-auth receives a gated resource', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/1'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // Bob is turned away (403), proving the resource IS access-controlled — yet a
    // logged-out request receives Alice's invoice verbatim. Anyone can read it.
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/1': {
        'session=alice': { status: 200, body: 'Invoice #1 — total $500' },
        'session=bob': { status: 403, body: 'forbidden' },
        '': { status: 200, body: 'Invoice #1 — total $500' },
      },
    });

    const { outcomes } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(1);
    const [outcome] = outcomes;
    expect(outcome?.category).toBe('unauthenticated-resource-access');
    expect(outcome?.url).toBe('https://app.test/invoice/1');
    expect(outcome?.ownerLabel).toBe('alice');
    // No idor is produced for this URL — the peer never received the ground truth.
    expect(outcomes.filter((o) => o.category === 'idor')).toHaveLength(0);
    // The proof carries digests and statuses, never any body content.
    const serialized = JSON.stringify(outcome?.proof);
    expect(serialized).not.toContain('Invoice');
    expect(serialized).not.toContain('$500');
    expect(outcome?.proof.owner.digest).toBe(outcome?.proof.noAuth.digest);
  });

  it('reports a stale-session error, and no finding, when the owner ground-truth fetch fails auth', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/1'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // Alice's own session has gone stale: her ground-truth fetch is bounced to login
    // (302). Bob happens to still receive the invoice — but without valid ground
    // truth there is nothing to compare against, so no finding may be fabricated.
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/1': {
        'session=alice': { status: 302, body: 'redirecting to /login' },
        'session=bob': { status: 200, body: 'Invoice #1 — total $500' },
        '': { status: 302, body: 'redirecting to /login' },
      },
    });

    const { outcomes, errors } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(0);
    expect(errors).toHaveLength(1);
    const [error] = errors;
    expect(error?.ownerLabel).toBe('alice');
    expect(error?.url).toBe('https://app.test/invoice/1');
    expect(error?.status).toBe(302);
    // The reported message names the identity so the operator knows which to re-supply.
    expect(error?.message).toContain('alice');
    // Never leaks the private body, even in the error path.
    expect(error?.message).not.toContain('Invoice');
  });

  it('reports a stale-session error on a 401 owner ground-truth fetch', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/1'] },
    ];
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/1': {
        'session=alice': { status: 401, body: 'unauthorized' },
        '': { status: 401, body: 'unauthorized' },
      },
    });

    const { outcomes, errors } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(0);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.status).toBe(401);
  });

  it('does not report a stale-session error for a plain 404/403 owner response', async () => {
    const identities: Identity[] = [
      { label: 'alice', headers: { cookie: 'session=alice' }, privateUrls: ['https://app.test/invoice/999'] },
      { label: 'bob', headers: { cookie: 'session=bob' }, privateUrls: [] },
    ];
    // A 404 is a genuine "not here", not a stale session — it stays a silent
    // no-finding, not a reported error.
    const fetchImpl = fakeFetch({
      'https://app.test/invoice/999': {
        'session=alice': { status: 404, body: 'Not found' },
        'session=bob': { status: 404, body: 'Not found' },
        '': { status: 302, body: 'login' },
      },
    });

    const { outcomes, errors } = await runAccessControlChecks(identities, fetchImpl);

    expect(outcomes).toHaveLength(0);
    expect(errors).toHaveLength(0);
  });
});
