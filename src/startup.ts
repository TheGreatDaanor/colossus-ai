export function assertAnthropicApiKey(env: Record<string, string | undefined>): void {
  if (!env['ANTHROPIC_API_KEY']) {
    throw new Error('ANTHROPIC_API_KEY must be set — LLM finding enrichment requires it.');
  }
}
