import { describe, expect, it } from 'vitest';
import { createDb } from '../db/client.js';
import { apexOf, classifyHost, ProgramValidationError, ProgramsService, type Scope } from './programs.js';

function scope(inList: string[], outList: string[] = []): Scope {
  return { in: inList, out: outList };
}

function buildService() {
  return new ProgramsService(createDb(':memory:'));
}

describe('apexOf', () => {
  it('returns the registrable domain of a plain hostname', () => {
    expect(apexOf('blog.example.com')).toBe('example.com');
  });

  it('returns the registrable domain across a multi-label public suffix', () => {
    expect(apexOf('shop.example.co.uk')).toBe('example.co.uk');
  });

  it('returns the hostname itself when it is already an apex', () => {
    expect(apexOf('example.com')).toBe('example.com');
  });

  it('normalises case and a trailing dot before computing the apex', () => {
    expect(apexOf('Blog.EXAMPLE.com.')).toBe('example.com');
  });

  it('returns null for a bare public suffix, which nobody can register', () => {
    expect(apexOf('co.uk')).toBeNull();
  });

  it('returns null for a hostname that is not a domain name', () => {
    expect(apexOf('not a host')).toBeNull();
  });
});

describe('classifyHost', () => {
  it('classifies a subdomain of an in-scope apex as in_scope', () => {
    expect(classifyHost('blog.example.com', scope(['example.com']))).toBe('in_scope');
  });

  it('classifies the in-scope apex itself as in_scope', () => {
    expect(classifyHost('example.com', scope(['example.com']))).toBe('in_scope');
  });

  it('classifies a deep subdomain of an in-scope apex as in_scope', () => {
    expect(classifyHost('a.b.c.example.com', scope(['example.com']))).toBe('in_scope');
  });

  it('classifies hosts under a second in-scope apex as in_scope, since a program is one engagement', () => {
    const engagement = scope(['example.com', 'example-shop.com']);

    expect(classifyHost('blog.example.com', engagement)).toBe('in_scope');
    expect(classifyHost('checkout.example-shop.com', engagement)).toBe('in_scope');
  });

  it('classifies an exact in-scope host as in_scope without pulling in its apex', () => {
    expect(classifyHost('blog.partner.com', scope(['blog.partner.com']))).toBe('in_scope');
  });

  it('classifies a sibling of an exact in-scope host as unscoped', () => {
    expect(classifyHost('www.partner.com', scope(['blog.partner.com']))).toBe('unscoped');
  });

  it('classifies a subdomain of an exact in-scope host as unscoped', () => {
    expect(classifyHost('cdn.blog.partner.com', scope(['blog.partner.com']))).toBe('unscoped');
  });

  it('classifies a host matching neither list as unscoped', () => {
    expect(classifyHost('example.org', scope(['example.com']))).toBe('unscoped');
  });

  it('classifies a host under an empty scope as unscoped, so nothing is scanned by default', () => {
    expect(classifyHost('example.com', scope([]))).toBe('unscoped');
  });

  it('lets an out-of-scope wildcard subtree beat an in-scope apex', () => {
    const engagement = scope(['example.com'], ['*.internal.example.com']);

    expect(classifyHost('vpn.internal.example.com', engagement)).toBe('out_of_scope');
  });

  it('treats a wildcard subtree as covering its own root', () => {
    expect(classifyHost('internal.example.com', scope(['example.com'], ['*.internal.example.com']))).toBe('out_of_scope');
  });

  it('leaves a sibling of an excluded subtree in scope', () => {
    expect(classifyHost('vpn.external.example.com', scope(['example.com'], ['*.internal.example.com']))).toBe('in_scope');
  });

  it('lets an exact out-of-scope host beat an in-scope apex', () => {
    expect(classifyHost('admin.example.com', scope(['example.com'], ['admin.example.com']))).toBe('out_of_scope');
  });

  it('does not let an exact out-of-scope host exclude its subdomains', () => {
    expect(classifyHost('eu.admin.example.com', scope(['example.com'], ['admin.example.com']))).toBe('in_scope');
  });

  it('lets an out-of-scope apex exclude a whole domain from the engagement', () => {
    expect(classifyHost('blog.example.net', scope(['example.com', 'example.net'], ['example.net']))).toBe('out_of_scope');
  });

  it('classifies an out-of-scope host as out_of_scope even when nothing is in scope', () => {
    expect(classifyHost('admin.example.com', scope([], ['admin.example.com']))).toBe('out_of_scope');
  });

  it('normalises case and a trailing dot on the host before matching', () => {
    expect(classifyHost('BLOG.example.com.', scope(['example.com']))).toBe('in_scope');
  });

  it('normalises case on the scope entry before matching', () => {
    expect(classifyHost('blog.example.com', scope(['EXAMPLE.com']))).toBe('in_scope');
  });

  it('does not let a suffix that is not a label boundary match an in-scope apex', () => {
    expect(classifyHost('notexample.com', scope(['example.com']))).toBe('unscoped');
  });

  it('keeps an in-scope apex under a multi-label public suffix from swallowing its neighbours', () => {
    const engagement = scope(['example.co.uk']);

    expect(classifyHost('blog.example.co.uk', engagement)).toBe('in_scope');
    expect(classifyHost('other.co.uk', engagement)).toBe('unscoped');
  });

  it('classifies a hostname that is not a domain name as unscoped', () => {
    expect(classifyHost('not a host', scope(['example.com']))).toBe('unscoped');
  });
});

describe('ProgramsService.createProgram', () => {
  it('seeds the apex of a submitted URL into the in-scope list', async () => {
    const service = buildService();

    const program = await service.createProgram({ url: 'https://example.com/x' });

    expect(program.scopeEntries).toEqual([expect.objectContaining({ list: 'in', pattern: 'example.com' })]);
  });

  it('seeds the apex of a subdomain URL rather than the submitted host', async () => {
    const service = buildService();

    const program = await service.createProgram({ url: 'https://blog.example.com/x' });

    expect(program.scopeEntries[0]?.pattern).toBe('example.com');
  });

  it('leaves a seeded apex unconfirmed, because a parser inferred it', async () => {
    const service = buildService();

    const program = await service.createProgram({ url: 'https://example.com/x' });

    expect(program.scopeEntries[0]?.confirmedAt).toBeNull();
  });

  it('names the program after the seeded apex when no name is given', async () => {
    const service = buildService();

    const program = await service.createProgram({ url: 'https://example.com/x' });

    expect(program.name).toBe('example.com');
  });

  it('keeps an explicit name over the seeded apex', async () => {
    const service = buildService();

    const program = await service.createProgram({ url: 'https://example.com/x', name: 'Acme engagement' });

    expect(program.name).toBe('Acme engagement');
  });

  it('creates a program with no scope entries when given only a name', async () => {
    const service = buildService();

    const program = await service.createProgram({ name: 'Acme engagement' });

    expect(program.scopeEntries).toEqual([]);
  });

  it('leaves both host caps null so the mode defaults apply', async () => {
    const service = buildService();

    const program = await service.createProgram({ name: 'Acme engagement' });

    expect(program.passiveHostCap).toBeNull();
    expect(program.activeHostCap).toBeNull();
  });

  it('stores per-program host cap overrides', async () => {
    const service = buildService();

    const program = await service.createProgram({ name: 'Acme', passiveHostCap: 500, activeHostCap: 10 });

    expect(program.passiveHostCap).toBe(500);
    expect(program.activeHostCap).toBe(10);
  });

  it('rejects a URL that is not http or https', async () => {
    const service = buildService();

    await expect(service.createProgram({ url: 'ftp://example.com' })).rejects.toThrow(ProgramValidationError);
  });

  it('rejects a URL whose host has no registrable apex', async () => {
    const service = buildService();

    await expect(service.createProgram({ url: 'https://co.uk' })).rejects.toThrow(ProgramValidationError);
  });

  it('rejects a program with neither a url nor a name', async () => {
    const service = buildService();

    await expect(service.createProgram({})).rejects.toThrow(ProgramValidationError);
  });
});

describe('ProgramsService.getProgram', () => {
  it('returns the program with its scope entries', async () => {
    const service = buildService();
    const created = await service.createProgram({ url: 'https://example.com' });

    const found = await service.getProgram(created.id);

    expect(found?.scopeEntries).toHaveLength(1);
  });

  it('returns null for an unknown program', async () => {
    const service = buildService();

    expect(await service.getProgram(404)).toBeNull();
  });
});

describe('ProgramsService.addScopeEntry', () => {
  it('adds a second in-scope apex to the engagement', async () => {
    const service = buildService();
    const program = await service.createProgram({ url: 'https://example.com' });

    await service.addScopeEntry(program.id, { list: 'in', pattern: 'example-shop.com' });

    const found = await service.getProgram(program.id);
    expect(found?.scopeEntries.map((e) => e.pattern)).toEqual(['example.com', 'example-shop.com']);
  });

  it('marks an operator-added entry confirmed, because it was typed rather than inferred', async () => {
    const service = buildService();
    const program = await service.createProgram({ name: 'Acme' });

    const entry = await service.addScopeEntry(program.id, { list: 'in', pattern: 'example.com' });

    expect(entry.confirmedAt).toBeInstanceOf(Date);
  });

  it('accepts a wildcard subtree on the out-of-scope list', async () => {
    const service = buildService();
    const program = await service.createProgram({ url: 'https://example.com' });

    const entry = await service.addScopeEntry(program.id, { list: 'out', pattern: '*.internal.example.com' });

    expect(entry.list).toBe('out');
  });

  it('normalises a pattern to lowercase without its trailing dot', async () => {
    const service = buildService();
    const program = await service.createProgram({ name: 'Acme' });

    const entry = await service.addScopeEntry(program.id, { list: 'in', pattern: 'EXAMPLE.com.' });

    expect(entry.pattern).toBe('example.com');
  });

  it('rejects a wildcard pattern on the in-scope list, which the grammar does not allow', async () => {
    const service = buildService();
    const program = await service.createProgram({ name: 'Acme' });

    await expect(service.addScopeEntry(program.id, { list: 'in', pattern: '*.example.com' })).rejects.toThrow(
      ProgramValidationError,
    );
  });

  it('rejects a pattern that is not a hostname', async () => {
    const service = buildService();
    const program = await service.createProgram({ name: 'Acme' });

    await expect(service.addScopeEntry(program.id, { list: 'in', pattern: 'https://example.com/x' })).rejects.toThrow(
      ProgramValidationError,
    );
  });

  it('rejects an empty pattern', async () => {
    const service = buildService();
    const program = await service.createProgram({ name: 'Acme' });

    await expect(service.addScopeEntry(program.id, { list: 'in', pattern: '  ' })).rejects.toThrow(ProgramValidationError);
  });

  it('rejects a duplicate pattern on the same list', async () => {
    const service = buildService();
    const program = await service.createProgram({ url: 'https://example.com' });

    await expect(service.addScopeEntry(program.id, { list: 'in', pattern: 'example.com' })).rejects.toThrow(
      ProgramValidationError,
    );
  });

  it('allows the same pattern on the other list, where the exclusion simply wins', async () => {
    const service = buildService();
    const program = await service.createProgram({ url: 'https://example.com' });

    const entry = await service.addScopeEntry(program.id, { list: 'out', pattern: 'example.com' });

    expect(entry.pattern).toBe('example.com');
  });

  it('rejects an entry on an unknown program', async () => {
    const service = buildService();

    await expect(service.addScopeEntry(404, { list: 'in', pattern: 'example.com' })).rejects.toThrow(
      ProgramValidationError,
    );
  });
});

describe('ProgramsService.removeScopeEntry', () => {
  it('removes the entry from the program', async () => {
    const service = buildService();
    const program = await service.createProgram({ url: 'https://example.com' });
    const entry = program.scopeEntries[0];
    if (!entry) throw new Error('expected a seeded scope entry');

    await service.removeScopeEntry(program.id, entry.id);

    const found = await service.getProgram(program.id);
    expect(found?.scopeEntries).toEqual([]);
  });

  it('rejects removing an entry that belongs to another program', async () => {
    const service = buildService();
    const mine = await service.createProgram({ url: 'https://example.com' });
    const theirs = await service.createProgram({ url: 'https://example.org' });
    const entry = theirs.scopeEntries[0];
    if (!entry) throw new Error('expected a seeded scope entry');

    await expect(service.removeScopeEntry(mine.id, entry.id)).rejects.toThrow(ProgramValidationError);
  });
});

describe('ProgramsService.classify', () => {
  it('classifies a host against the program as stored', async () => {
    const service = buildService();
    const program = await service.createProgram({ url: 'https://example.com/x' });
    await service.addScopeEntry(program.id, { list: 'out', pattern: '*.internal.example.com' });

    expect(await service.classify(program.id, 'blog.example.com')).toBe('in_scope');
    expect(await service.classify(program.id, 'vpn.internal.example.com')).toBe('out_of_scope');
    expect(await service.classify(program.id, 'example.org')).toBe('unscoped');
  });

  it('rejects classification against an unknown program', async () => {
    const service = buildService();

    await expect(service.classify(404, 'example.com')).rejects.toThrow(ProgramValidationError);
  });
});
