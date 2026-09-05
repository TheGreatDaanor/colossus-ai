import { chromium, type Browser } from 'playwright';
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

// `confirmed` means the marker actually executed; `not_vulnerable` means the page
// loaded and it did not; `unavailable` means we could not tell. Collapsing the last
// two would destroy the PRD's "not vulnerable vs. couldn't test it" distinction.
export type XssOutcome = 'confirmed' | 'not_vulnerable' | 'unavailable';
export type XssAttemptResult = { outcome: XssOutcome; error?: string };

// The payload sets `window.__colossus_xss_marker` to a UUID; execution is detected
// by reading that property back and matching the UUID out of the payload we sent.
function markerOf(payload: string): string | null {
  return /__colossus_xss_marker\s*=\s*'([^']+)'/.exec(payload)?.[1] ?? null;
}

// Retry once on browser *launch* failure only — a launch failure is infrastructure
// and usually transient. A failed navigation is not retried: it will fail again, and
// retrying doubles the time a hostile target can hold a browser context. A navigation
// timeout is `unavailable`, never `not_vulnerable` — telling them apart is the point.
export async function confirmXss(
  url: string,
  payload: string,
  options: { navigationTimeoutMs?: number } = {},
): Promise<XssAttemptResult> {
  const marker = markerOf(payload);
  if (marker === null) return { outcome: 'unavailable', error: 'payload carries no marker' };

  let browser: Browser;
  try {
    browser = await chromium.launch();
  } catch {
    try {
      browser = await chromium.launch();
    } catch (err) {
      return { outcome: 'unavailable', error: `browser launch failed: ${errorMessage(err)}` };
    }
  }

  try {
    const page = await browser.newPage();
    try {
      await page.goto(url, { timeout: options.navigationTimeoutMs ?? 10_000 });
    } catch (err) {
      return { outcome: 'unavailable', error: `navigation failed: ${errorMessage(err)}` };
    }
    const observed = await page.evaluate(
      () => (globalThis as { __colossus_xss_marker?: string }).__colossus_xss_marker,
    );
    return { outcome: observed === marker ? 'confirmed' : 'not_vulnerable' };
  } finally {
    await browser.close();
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// The scanner injects this at its boundary so every test but the real-browser
// fixture can drive confirmation outcomes without launching Chromium.
export type XssConfirmImpl = (url: string, payload: string) => Promise<XssAttemptResult>;
