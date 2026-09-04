import { randomUUID } from 'node:crypto';

export type InjectionAttempt = {
  param: string;
  payload: string;
  url: string;
};

export function generateCanaryPayload(): string {
  return `<script>window.__colossus_xss_marker='${randomUUID()}'</script>`;
}

export function enumerateInjectionAttempts(rawUrl: string): InjectionAttempt[] {
  const url = new URL(rawUrl);
  const params = Array.from(url.searchParams.keys());

  return params.map((param) => {
    const payload = generateCanaryPayload();
    const mutated = new URL(rawUrl);
    mutated.searchParams.set(param, payload);
    return { param, payload, url: mutated.toString() };
  });
}
