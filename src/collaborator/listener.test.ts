import { describe, expect, it } from 'vitest';
import { buildDnsAnswer, isIpv4Address, parseDnsQuestion, respondToDns } from './dns.js';
import { HitBuffer, tokenFromHostname } from './hit-buffer.js';
import { mintSignedToken, isSignedToken } from './token.js';
import { createQueryApi } from './query-api.js';

describe('tokenFromHostname', () => {
  const base = 'oast.example.net';

  it.each([
    ['abcdefghij234567abcd.oast.example.net', 'abcdefghij234567abcd'],
    ['ABCDEFGHIJ234567ABCD.OAST.example.net.', 'abcdefghij234567abcd'],
    // A target may prefix labels of its own; the token is the label under the base.
    ['www.abcdefghij234567abcd.oast.example.net', 'abcdefghij234567abcd'],
    ['abcdefghij234567abcd.oast.example.net:80', 'abcdefghij234567abcd'],
  ])('reads the token from %s', (host, token) => {
    expect(tokenFromHostname(host, base)).toBe(token);
  });

  it.each([['oast.example.net'], ['evil-oast.example.net'], ['abc.other.net'], ['']])(
    'finds no token in %s',
    (host) => {
      expect(tokenFromHostname(host, base)).toBeNull();
    },
  );
});

describe('HitBuffer', () => {
  it('returns the hits recorded for the asked tokens only', () => {
    const buffer = new HitBuffer({ ttlMs: 60_000, maxHits: 100, now: () => 1_000 });
    buffer.record({ token: 'a', protocol: 'dns', callerSourceIp: '198.51.100.53' });
    buffer.record({ token: 'b', protocol: 'http', callerSourceIp: '203.0.113.7' });

    expect(buffer.query(['a'])).toEqual([
      { token: 'a', protocol: 'dns', callerSourceIp: '198.51.100.53', observedAt: new Date(1_000).toISOString() },
    ]);
  });

  it('forgets hits older than the ttl', () => {
    let now = 0;
    const buffer = new HitBuffer({ ttlMs: 600_000, maxHits: 100, now: () => now });
    buffer.record({ token: 'a', protocol: 'dns', callerSourceIp: '198.51.100.53' });
    now = 600_001;

    expect(buffer.query(['a'])).toEqual([]);
  });

  it('stays bounded, evicting the oldest hits first', () => {
    let now = 0;
    const buffer = new HitBuffer({ ttlMs: 600_000, maxHits: 2, now: () => now++ });
    buffer.record({ token: 'a', protocol: 'dns', callerSourceIp: '1.1.1.1' });
    buffer.record({ token: 'b', protocol: 'dns', callerSourceIp: '1.1.1.1' });
    buffer.record({ token: 'c', protocol: 'dns', callerSourceIp: '1.1.1.1' });

    expect(buffer.size).toBe(2);
    expect(buffer.query(['a', 'b', 'c']).map((h) => h.token)).toEqual(['b', 'c']);
  });
});

describe('signed tokens', () => {
  it('accepts a token minted with the same secret, and nothing forged or minted with another', () => {
    const token = mintSignedToken('s3cret');

    expect(token).toMatch(/^[a-z2-7]{20}$/);
    expect(isSignedToken('s3cret', token)).toBe(true);
    expect(isSignedToken('other', token)).toBe(false);
    expect(isSignedToken('s3cret', `${token.slice(0, 19)}${token.endsWith('a') ? 'b' : 'a'}`)).toBe(false);
    expect(isSignedToken('s3cret', 'aaaaaaaaaaaaaaaaaaaa')).toBe(false);
    expect(isSignedToken('s3cret', 'short')).toBe(false);
  });

  it('keeps a buffer that only accepts signed tokens from being flooded out by unsigned ones', () => {
    const buffer = new HitBuffer({ ttlMs: 600_000, maxHits: 2, now: () => 0, accepts: (t) => isSignedToken('s3cret', t) });
    const real = mintSignedToken('s3cret');
    buffer.record({ token: real, protocol: 'http', callerSourceIp: '203.0.113.7' });
    for (let i = 0; i < 10; i += 1) buffer.record({ token: `junk${i}`, protocol: 'dns', callerSourceIp: '198.51.100.1' });

    expect(buffer.query([real]).map((h) => h.token)).toEqual([real]);
  });
});

describe('query api', () => {
  const buffer = new HitBuffer({ ttlMs: 600_000, maxHits: 100, now: () => 0 });
  buffer.record({ token: 'a', protocol: 'http', callerSourceIp: '203.0.113.7' });
  const app = createQueryApi(buffer, 's3cret');
  const ask = (authorization: string | null, body: unknown = { tokens: ['a'] }) =>
    app.request('/hits', {
      method: 'POST',
      headers: authorization === null ? {} : { authorization },
      body: JSON.stringify(body),
    });

  it('answers hits for the asked tokens when the secret matches', async () => {
    const response = await ask('Bearer s3cret');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      hits: [{ token: 'a', protocol: 'http', callerSourceIp: '203.0.113.7', observedAt: new Date(0).toISOString() }],
    });
  });

  it.each([[null], ['Bearer wrong'], ['Bearer s3cret-but-longer'], ['s3cret']])(
    'refuses a request with authorization %s',
    async (authorization) => {
      expect((await ask(authorization)).status).toBe(401);
    },
  );

  it('rejects a body without a token list', async () => {
    expect((await ask('Bearer s3cret', { tokens: 'a' })).status).toBe(400);
  });
});

describe('dns packets', () => {
  // A standard recursive query for `name` (type A, class IN), id 0x1234.
  function query(name: string, type = 1): Buffer {
    const labels = name.split('.').flatMap((label) => [label.length, ...Buffer.from(label)]);
    return Buffer.from([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, type, 0, 1]);
  }

  it('parses the question name and type', () => {
    expect(parseDnsQuestion(query('tok.oast.example.net'))).toEqual({
      id: 0x1234,
      name: 'tok.oast.example.net',
      type: 1,
      questionEnd: 12 + 'tok.oast.example.net'.length + 2 + 4,
    });
  });

  it('refuses malformed packets', () => {
    expect(parseDnsQuestion(Buffer.from([0x12, 0x34]))).toBeNull();
    // A label length running past the end of the packet.
    expect(parseDnsQuestion(Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 40, 0x61]))).toBeNull();
  });

  it('answers an A query authoritatively with the listener address', () => {
    const packet = query('tok.oast.example.net');
    const question = parseDnsQuestion(packet)!;
    const answer = buildDnsAnswer(packet, question, '192.0.2.53');

    expect(answer.readUInt16BE(0)).toBe(0x1234);
    // QR=1, AA=1, RD copied, RCODE=0.
    expect(answer.readUInt16BE(2) & 0x8400).toBe(0x8400);
    expect(answer.readUInt16BE(2) & 0x000f).toBe(0);
    expect(answer.readUInt16BE(6)).toBe(1); // ANCOUNT
    expect([...answer.subarray(answer.length - 4)]).toEqual([192, 0, 2, 53]);
  });

  it('ignores responses and non-QUERY opcodes, so it never answers an answer', () => {
    const response = query('tok.oast.example.net');
    response.writeUInt16BE(0x8000, 2); // QR=1
    const notify = query('tok.oast.example.net');
    notify.writeUInt16BE(4 << 11, 2); // opcode NOTIFY

    expect(respondToDns(response, 'oast.example.net', '192.0.2.53')).toBeNull();
    expect(respondToDns(notify, 'oast.example.net', '192.0.2.53')).toBeNull();
  });

  it('refuses names outside its zone instead of answering them authoritatively', () => {
    const answer = respondToDns(query('google.com'), 'oast.example.net', '192.0.2.53')!;

    expect(answer.readUInt16BE(2) & 0x000f).toBe(5); // RCODE REFUSED
    expect(answer.readUInt16BE(2) & 0x0400).toBe(0); // not authoritative
    expect(answer.readUInt16BE(6)).toBe(0);
  });

  it('answers names in its zone, and the zone apex itself', () => {
    for (const name of ['tok.oast.example.net', 'OAST.example.net']) {
      const answer = respondToDns(query(name), 'oast.example.net', '192.0.2.53')!;
      expect([...answer.subarray(answer.length - 4)]).toEqual([192, 0, 2, 53]);
    }
  });

  it('accepts only a dotted-quad IPv4 listener address', () => {
    expect(isIpv4Address('192.0.2.53')).toBe(true);
    for (const bad of ['203.0.113.300', '2001:db8::1', '1.2.3', '1.2.3.4.5', '']) expect(isIpv4Address(bad)).toBe(false);
  });

  it('answers a non-A query with no records, still authoritatively', () => {
    const packet = query('tok.oast.example.net', 28); // AAAA
    const answer = buildDnsAnswer(packet, parseDnsQuestion(packet)!, '192.0.2.53');

    expect(answer.readUInt16BE(6)).toBe(0);
    expect(answer.readUInt16BE(2) & 0x8400).toBe(0x8400);
  });
});
