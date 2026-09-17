import { chromium, type Browser, type Page } from 'playwright';
import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { InjectionAttempt } from '../db/schema.js';
import { findDisallowedAddress } from './ssrf-guard.js';

// Confirmed-finding evidence lives here, one directory per scan. `data/` is
// gitignored in full, so nothing extra is needed to keep screenshots out of git.
const EVIDENCE_ROOT = 'data/evidence';

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
// `screenshot` is captured only on a `confirmed` outcome — proof the marker executed
// in a real browser. The scanner writes it to disk under the confirmed finding's id.
export type XssAttemptResult = { outcome: XssOutcome; error?: string; screenshot?: Buffer };

// Writes a confirmation screenshot to data/evidence/<scanId>/<findingId>.png and
// returns that relative path. The file is named after the finding id (a value this
// codebase controls), never the payload marker. Written once and never deleted:
// evidence you auto-delete is evidence you don't have when you need it.
export async function saveEvidence(scanId: number, findingId: number, screenshot: Buffer): Promise<string> {
  const dir = join(EVIDENCE_ROOT, String(scanId));
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${findingId}.png`);
  await writeFile(path, screenshot);
  return path;
}

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
    const blockedAddress = await installNavigationGuard(page);
    try {
      await page.goto(url, { timeout: options.navigationTimeoutMs ?? 10_000 });
    } catch (err) {
      const blocked = blockedAddress();
      if (blocked !== null) {
        return { outcome: 'unavailable', error: `navigation to a disallowed address (${blocked}) was blocked` };
      }
      return { outcome: 'unavailable', error: `navigation failed: ${errorMessage(err)}` };
    }
    const blocked = blockedAddress();
    if (blocked !== null) {
      return { outcome: 'unavailable', error: `a request to a disallowed address (${blocked}) was blocked` };
    }
    const observed = await page.evaluate(
      () => (globalThis as { __colossus_xss_marker?: string }).__colossus_xss_marker,
    );
    if (observed !== marker) return { outcome: 'not_vulnerable' };
    return { outcome: 'confirmed', screenshot: await page.screenshot() };
  } finally {
    await browser.close();
  }
}

// Installs the SSRF guard on a page's own requests. The operator-submitted target —
// the first main-frame navigation — is trusted: it already cleared the passive guard
// in the scanner before a browser was launched at all. Every request after it (a
// redirect, a sub-frame, a sub-resource) is resolved and checked against the same
// disallowed-address table, and any pointing at a private/loopback/link-local/
// metadata address is aborted, so active scanning can't become an SSRF hole. Returns
// a getter for the first address blocked, if any.
async function installNavigationGuard(page: Page): Promise<() => string | null> {
  let blocked: string | null = null;
  let trustedFirstNavigationSeen = false;
  const api = page.context().request;

  // Resolves the request's hostname and records the first disallowed address it hits.
  const disallowedAddressFor = async (requestUrl: string): Promise<string | null> => {
    let hostname: string;
    try {
      hostname = new URL(requestUrl).hostname;
    } catch {
      return null;
    }
    const disallowed = await findDisallowedAddress(hostname);
    if (disallowed !== null && blocked === null) blocked = disallowed;
    return disallowed;
  };

  await page.route('**/*', async (route) => {
    const request = route.request();
    const isTopLevelNavigation = request.isNavigationRequest() && request.frame() === page.mainFrame();

    // Sub-resources and sub-frames don't auto-follow redirects behind our back the way
    // a top-level navigation does, so guarding the request URL itself is enough here.
    if (!isTopLevelNavigation) {
      if ((await disallowedAddressFor(request.url())) !== null) {
        await route.abort();
        return;
      }
      await route.continue();
      return;
    }

    // The operator-submitted target — the first main-frame navigation — is the one
    // request we don't guard: it already cleared the passive guard in the scanner.
    // A later top-level navigation (a client-side location change) is guarded.
    if (!trustedFirstNavigationSeen) {
      trustedFirstNavigationSeen = true;
    } else if ((await disallowedAddressFor(request.url())) !== null) {
      await route.abort();
      return;
    }

    // Follow redirects ourselves, guarding every hop, rather than `route.continue()`:
    // that would hand redirect-following to the browser's network stack, which would
    // connect to a disallowed `Location` before this handler ever saw it.
    try {
      let currentUrl = request.url();
      let response = await api.get(currentUrl, { maxRedirects: 0 });
      for (let hops = 0; hops < 20; hops++) {
        const status = response.status();
        const location = response.headers()['location'];
        if (status < 300 || status >= 400 || location === undefined) break;
        const nextUrl = new URL(location, currentUrl).toString();
        if ((await disallowedAddressFor(nextUrl)) !== null) {
          await route.abort();
          return;
        }
        currentUrl = nextUrl;
        response = await api.get(currentUrl, { maxRedirects: 0 });
      }
      await route.fulfill({ response });
    } catch {
      await route.abort();
    }
  });

  return () => blocked;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// The scanner injects this at its boundary so every test but the real-browser
// fixture can drive confirmation outcomes without launching Chromium.
export type XssConfirmImpl = (url: string, payload: string) => Promise<XssAttemptResult>;
