import { describe, expect, it } from 'vitest';
import { enumerateInjectionAttempts, generateCanaryPayload } from './active-scanner.js';

describe('generateCanaryPayload', () => {
  it('produces a unique marker on each call', () => {
    const a = generateCanaryPayload();
    const b = generateCanaryPayload();

    expect(a).not.toEqual(b);
  });
});

describe('enumerateInjectionAttempts', () => {
  it('produces one attempt per query parameter, each with a unique payload', () => {
    const attempts = enumerateInjectionAttempts('https://example.com/search?q=test&page=2');

    expect(attempts).toHaveLength(2);
    expect(attempts.map((a) => a.param).sort()).toEqual(['page', 'q']);
    expect(attempts[0]?.payload).not.toEqual(attempts[1]?.payload);
  });

  it('mutates only the targeted parameter, leaving others untouched', () => {
    const attempts = enumerateInjectionAttempts('https://example.com/search?q=test&page=2');

    const qAttempt = attempts.find((a) => a.param === 'q');
    expect(qAttempt).toBeDefined();
    const mutatedUrl = new URL(qAttempt!.url);
    expect(mutatedUrl.searchParams.get('q')).toBe(qAttempt!.payload);
    expect(mutatedUrl.searchParams.get('page')).toBe('2');
  });

  it('produces zero attempts for a URL with no query parameters', () => {
    expect(enumerateInjectionAttempts('https://example.com/search')).toEqual([]);
  });
});
