import { describe, expect, it } from 'vitest';
import { assertAnthropicApiKey } from './startup.js';

describe('assertAnthropicApiKey', () => {
  it('throws a clear error when ANTHROPIC_API_KEY is missing', () => {
    expect(() => assertAnthropicApiKey({})).toThrow(/ANTHROPIC_API_KEY/);
  });

  it('throws when ANTHROPIC_API_KEY is an empty string', () => {
    expect(() => assertAnthropicApiKey({ ANTHROPIC_API_KEY: '' })).toThrow(/ANTHROPIC_API_KEY/);
  });

  it('does not throw when ANTHROPIC_API_KEY is set', () => {
    expect(() => assertAnthropicApiKey({ ANTHROPIC_API_KEY: 'sk-test' })).not.toThrow();
  });
});
