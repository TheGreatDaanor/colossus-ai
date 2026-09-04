import { randomUUID } from 'node:crypto';
import type { InjectionAttempt } from '../db/schema.js';

// A single query-parameter injection point: which parameter was targeted, the
// unique canary payload put in its place, and the resulting URL to fetch.
export type InjectionPoint = InjectionAttempt & { url: string };

// Produces a fresh unique marker per attempt. The UUID makes the marker
// unmistakably ours when 011 checks whether it executed in the browser — no other
// value on the page can collide with it.
export function generateCanaryPayload(): string {
  return `<script>window.__colossus_xss_marker='${randomUUID()}'</script>`;
}

// Enumerates a URL's query parameters and, for each one, produces a mutated URL
// with that parameter's value replaced by a fresh canary payload. A URL with no
// query parameters yields no injection points (not an error). Order follows the
// query string so attempts are stable and inspectable.
export function enumerateInjectionPoints(targetUrl: URL): InjectionPoint[] {
  const points: InjectionPoint[] = [];
  for (const injectionPoint of new Set(targetUrl.searchParams.keys())) {
    const payload = generateCanaryPayload();
    const mutated = new URL(targetUrl);
    mutated.searchParams.set(injectionPoint, payload);
    points.push({ injectionPoint, payload, url: mutated.toString() });
  }
  return points;
}
