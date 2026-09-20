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
export function enumerateInjectionPoints(
  targetUrl: URL,
  makePayload: () => string = generateCanaryPayload,
): InjectionPoint[] {
  const points: InjectionPoint[] = [];
  for (const injectionPoint of new Set(targetUrl.searchParams.keys())) {
    const payload = makePayload();
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
export type XssAttemptResult = {
  outcome: XssOutcome;
  error?: string;
  screenshot?: Buffer;
  // Oracle-confirmed non-XSS classes prove themselves with a response substring
  // rather than a screenshot; this carries it to the finding's `evidence_snippet`.
  evidenceSnippet?: string;
};

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

// The strategy seam every injection class plugs into: it names its finding
// category, enumerates a target's injection points, and confirms one point.
// XSS is its first implementation; SSTI/SQLi/LFI follow behind the same shape.
export interface InjectionClass {
  readonly category: string;
  enumerate(target: URL): InjectionPoint[];
  confirm(point: InjectionPoint): Promise<XssAttemptResult>;
}

// Reflected-XSS as an InjectionClass: enumeration and browser confirmation are
// the existing functions, unchanged, reached through the interface. `confirm`
// accepts an injected confirmer so the scanner can still mock it at its boundary.
export function makeXssInjectionClass(confirmImpl: XssConfirmImpl = confirmXss): InjectionClass {
  return {
    category: 'xss',
    enumerate: enumerateInjectionPoints,
    confirm: (point) => confirmImpl(point.url, point.payload),
  };
}

// The default XSS class, backed by the real browser confirmer.
export const xssInjectionClass: InjectionClass = makeXssInjectionClass();

// Fetches a URL's response body and headers. The content-based classes confirm by
// body, not by browser, so they fetch through this seam — the scanner injects its
// SSRF-guarded fetch, and `guardedFetchText` is the default for standalone use.
// Headers ride along so a class that needs them (CRLF injection) can inspect the
// response without a second fetch; the body-based classes read `.body` and ignore
// `.headers`.
export type BodyFetchImpl = (url: string) => Promise<{ body: string; headers: Headers }>;

// Produces a fresh arithmetic-oracle payload: two random factors wrapped in the two
// most common template delimiters (`${...}` for JSP/EL/Freemarker, `{{...}}` for
// Jinja/Twig/Handlebars), so one attempt reaches several engines. Factors are 4-digit
// so their product is 7-8 digits — long enough not to appear on a page by accident,
// which the baseline fetch double-checks. The literal `a*b` expression is recoverable
// from the payload, so confirmation needs nothing stored alongside it.
export function generateSstiPayload(): string {
  const factor = (): number => 1000 + Math.floor(Math.random() * 9000);
  const a = factor();
  const b = factor();
  return `\${${a}*${b}}{{${a}*${b}}}`;
}

// Recovers the two factors from a payload generated above, or null if the string
// carries no `<int>*<int>` expression (so a hand-built or malformed point is
// `unavailable`, never silently confirmed).
function factorsOf(payload: string): { literal: string; product: string } | null {
  const match = /(\d+)\*(\d+)/.exec(payload);
  if (match === null) return null;
  return { literal: `${match[1]}*${match[2]}`, product: String(Number(match[1]) * Number(match[2])) };
}

// The confirmed product plus a little surrounding context, so the finding's evidence
// shows where in the response the evaluated value landed rather than a bare number.
function snippetAround(body: string, needle: string, context = 40): string {
  const at = body.indexOf(needle);
  if (at === -1) return needle;
  return body.slice(Math.max(0, at - context), at + needle.length + context);
}

// A baseline URL for the same point with the parameter set to a neutral, non-arithmetic
// value: fetching it tells us whether the product already appears on the page for
// reasons unrelated to our injection, which would otherwise be a false positive.
function baselineUrlFor(point: InjectionPoint): string {
  const url = new URL(point.url);
  url.searchParams.set(point.injectionPoint, 'colossus_ssti_baseline');
  return url.toString();
}

// Resolves the host and refuses a disallowed (private/loopback/link-local/metadata)
// address before fetching, so the SSTI confirmer can't be pointed at internal
// infrastructure. The scanner injects its own already-guarded fetch instead; this is
// the default for standalone use.
async function guardedFetchText(url: string): Promise<{ body: string; headers: Headers }> {
  const disallowed = await findDisallowedAddress(new URL(url).hostname);
  if (disallowed !== null) throw new Error(`fetch to a disallowed address (${disallowed}) was blocked`);
  const response = await fetch(url, { redirect: 'manual' });
  return { body: await response.text(), headers: response.headers };
}

// Server-side template injection as an InjectionClass: enumeration mutates each query
// param with a fresh arithmetic payload; confirmation fetches the injected and a
// baseline response and confirms iff the engine *evaluated* the expression — the
// product appears in the injected body, the literal `a*b` does not, and the product
// was not already present in the baseline. A page that echoes the literal expression
// unchanged is `not_vulnerable`; a fetch that fails is `unavailable`.
export function makeSstiInjectionClass(fetchImpl: BodyFetchImpl = guardedFetchText): InjectionClass {
  return {
    category: 'ssti',
    enumerate: (target) => enumerateInjectionPoints(target, generateSstiPayload),
    confirm: async (point) => {
      const factors = factorsOf(point.payload);
      if (factors === null) return { outcome: 'unavailable', error: 'payload carries no arithmetic expression' };

      let injectedBody: string;
      try {
        injectedBody = (await fetchImpl(point.url)).body;
      } catch (err) {
        return { outcome: 'unavailable', error: `injection fetch failed: ${errorMessage(err)}` };
      }

      // The engine echoed our expression verbatim, or never produced the product:
      // reflected but not evaluated.
      if (injectedBody.includes(factors.literal)) return { outcome: 'not_vulnerable' };
      if (!injectedBody.includes(factors.product)) return { outcome: 'not_vulnerable' };

      // The product is in the injected body and the expression isn't — evaluated, unless
      // the number was already on the page for unrelated reasons. A baseline we can't
      // fetch can't clear that doubt, so we can't confirm.
      let baselineBody: string;
      try {
        baselineBody = (await fetchImpl(baselineUrlFor(point))).body;
      } catch (err) {
        return { outcome: 'unavailable', error: `baseline fetch failed: ${errorMessage(err)}` };
      }
      if (baselineBody.includes(factors.product)) return { outcome: 'not_vulnerable' };

      return { outcome: 'confirmed', evidenceSnippet: snippetAround(injectedBody, factors.product) };
    },
  };
}

// The default SSTI class, backed by the SSRF-guarded content fetcher.
export const sstiInjectionClass: InjectionClass = makeSstiInjectionClass();

// A single unbalanced quote: the smallest token that breaks the syntax of a naively
// concatenated SQL string, provoking the backend's own error page when the value
// reaches the database unescaped.
const SQLI_TOKEN = "'";

// Known database error signatures, one per common engine. A match proves the token
// reached the SQL parser rather than being escaped or rejected upstream; the
// differential against the baseline rules out signatures a page shows unconditionally.
const SQL_ERROR_SIGNATURES: RegExp[] = [
  /You have an error in your SQL syntax/i, // MySQL / MariaDB
  /SQL syntax.*MySQL/i,
  /ORA-\d{5}/, // Oracle
  /PG::\w*Error/, // PostgreSQL (Rails/pg)
  /PostgreSQL.*ERROR/i,
  /SQLITE_ERROR/, // SQLite
  /unrecognized token/i, // SQLite parser
  /SqlException/, // .NET / SQL Server
  /Unclosed quotation mark after the character string/i, // SQL Server
  /Microsoft OLE DB Provider for (?:ODBC|SQL Server)/i,
];

// The first line of the injected body that carries a DB error signature, so the finding's
// evidence quotes the message that proved the injection rather than the whole page.
function matchedErrorLine(body: string): string | null {
  for (const line of body.split(/\r?\n/)) {
    if (SQL_ERROR_SIGNATURES.some((sig) => sig.test(line))) return line.trim();
  }
  return null;
}

// A baseline URL for the same point with a neutral, non-breaking value, so a DB error
// the page emits regardless of our token (already present in the baseline) doesn't read
// as a confirmation.
function sqliBaselineUrlFor(point: InjectionPoint): string {
  const url = new URL(point.url);
  url.searchParams.set(point.injectionPoint, 'colossus_sqli_baseline');
  return url.toString();
}

// Error-based SQL injection as an InjectionClass: enumeration puts a single unbalanced
// quote in each query param; confirmation fetches the injected and a baseline response
// and confirms iff a known DB error signature appears in the injected body and was absent
// from the baseline. A page with no signature — or one that shows it unconditionally — is
// `not_vulnerable`; a fetch that fails is `unavailable`.
export function makeSqliInjectionClass(fetchImpl: BodyFetchImpl = guardedFetchText): InjectionClass {
  return {
    category: 'sqli',
    enumerate: (target) => enumerateInjectionPoints(target, () => SQLI_TOKEN),
    confirm: async (point) => {
      let injectedBody: string;
      try {
        injectedBody = (await fetchImpl(point.url)).body;
      } catch (err) {
        return { outcome: 'unavailable', error: `injection fetch failed: ${errorMessage(err)}` };
      }

      const errorLine = matchedErrorLine(injectedBody);
      if (errorLine === null) return { outcome: 'not_vulnerable' };

      // A signature is present, but only an injection proves it: if the baseline shows
      // one too, the page emits it unconditionally. A baseline we can't fetch can't
      // clear that doubt, so we can't confirm.
      let baselineBody: string;
      try {
        baselineBody = (await fetchImpl(sqliBaselineUrlFor(point))).body;
      } catch (err) {
        return { outcome: 'unavailable', error: `baseline fetch failed: ${errorMessage(err)}` };
      }
      if (matchedErrorLine(baselineBody) !== null) return { outcome: 'not_vulnerable' };

      return { outcome: 'confirmed', evidenceSnippet: errorLine };
    },
  };
}

// The default SQLi class, backed by the SSRF-guarded content fetcher.
export const sqliInjectionClass: InjectionClass = makeSqliInjectionClass();

// A path-traversal payload aimed at a file whose contents are stable across Unix
// systems. Enough `../` to climb out of any plausible include directory; the depth
// is harmless when it overshoots, since a leading-slash-normalised path still lands
// on the filesystem root.
const LFI_PAYLOAD = '../../../../etc/passwd';

// The `/etc/passwd` signature: the root account's entry, uid and gid zero. A line
// this shaped doesn't appear on a page by accident, and its presence proves the
// traversal resolved to the real file rather than being echoed as a string.
const PASSWD_SIGNATURE = /root:.*:0:0:/;

// The first line of the body carrying the passwd signature, so the finding's evidence
// quotes the line that proved the inclusion rather than the whole file.
function matchedPasswdLine(body: string): string | null {
  for (const line of body.split(/\r?\n/)) {
    if (PASSWD_SIGNATURE.test(line)) return line.trim();
  }
  return null;
}

// A baseline URL for the same point with a neutral, non-traversing value, so passwd-like
// content the page emits regardless of our payload (already present in the baseline)
// doesn't read as a confirmation.
function lfiBaselineUrlFor(point: InjectionPoint): string {
  const url = new URL(point.url);
  url.searchParams.set(point.injectionPoint, 'colossus_lfi_baseline');
  return url.toString();
}

// Local file inclusion as an InjectionClass: enumeration mutates each query param with a
// path-traversal payload toward `/etc/passwd`; confirmation fetches the injected and a
// baseline response and confirms iff the passwd signature appears in the injected body
// and was absent from the baseline. A page that echoes the payload or 404s (no signature)
// is `not_vulnerable`; a page that shows the signature unconditionally is `not_vulnerable`;
// a fetch that fails is `unavailable`.
export function makeLfiInjectionClass(fetchImpl: BodyFetchImpl = guardedFetchText): InjectionClass {
  return {
    category: 'lfi',
    enumerate: (target) => enumerateInjectionPoints(target, () => LFI_PAYLOAD),
    confirm: async (point) => {
      let injectedBody: string;
      try {
        injectedBody = (await fetchImpl(point.url)).body;
      } catch (err) {
        return { outcome: 'unavailable', error: `injection fetch failed: ${errorMessage(err)}` };
      }

      const passwdLine = matchedPasswdLine(injectedBody);
      if (passwdLine === null) return { outcome: 'not_vulnerable' };

      // The signature is present, but only the traversal proves it: if the baseline shows
      // it too, the page emits it unconditionally. A baseline we can't fetch can't clear
      // that doubt, so we can't confirm.
      let baselineBody: string;
      try {
        baselineBody = (await fetchImpl(lfiBaselineUrlFor(point))).body;
      } catch (err) {
        return { outcome: 'unavailable', error: `baseline fetch failed: ${errorMessage(err)}` };
      }
      if (matchedPasswdLine(baselineBody) !== null) return { outcome: 'not_vulnerable' };

      return { outcome: 'confirmed', evidenceSnippet: passwdLine };
    },
  };
}

// The default LFI class, backed by the SSRF-guarded content fetcher.
export const lfiInjectionClass: InjectionClass = makeLfiInjectionClass();

// A CRLF payload: a carriage-return/line-feed pair followed by a uniquely-valued
// header line. Enumeration URL-encodes the CR and LF to `%0d%0a`, so a target that
// copies the parameter into a response header unescaped terminates the current header
// and starts ours. The name is fixed (recoverable) and the value is a nonce, so the
// injected header can't collide with anything the server already sends.
export function generateCrlfPayload(): string {
  return `\r\nX-Colossus-CRLF: ${randomUUID().replace(/-/g, '')}`;
}

// Recovers the injected header's name and value from a payload generated above, or
// null if the string carries no `\r\n<name>: <value>` line (so a hand-built or
// malformed point is `unavailable`, never silently confirmed).
function injectedHeaderOf(payload: string): { name: string; value: string } | null {
  const match = /\r\n([\w-]+):[ \t]*(.+)$/.exec(payload);
  if (match === null) return null;
  return { name: match[1]!, value: match[2]! };
}

// A baseline URL for the same point with a neutral value carrying no CRLF, so an
// injected header the differential attributes to us is only counted when it's absent
// without the payload.
function crlfBaselineUrlFor(point: InjectionPoint): string {
  const url = new URL(point.url);
  url.searchParams.set(point.injectionPoint, 'colossus_crlf_baseline');
  return url.toString();
}

// CRLF (header) injection as an InjectionClass: enumeration mutates each query param
// with a `%0d%0a`-crafted, nonce-named header payload; confirmation fetches the injected
// and a baseline response and confirms iff the injected header appears in the injected
// response's headers with its nonce value and was absent from the baseline's. A param
// echoed into the body but not split into a header is `not_vulnerable`; a fetch that
// fails is `unavailable`. The oracle proves only that a header was injected — not a full
// response split.
export function makeCrlfInjectionClass(fetchImpl: BodyFetchImpl = guardedFetchText): InjectionClass {
  return {
    category: 'crlf-injection',
    enumerate: (target) => enumerateInjectionPoints(target, generateCrlfPayload),
    confirm: async (point) => {
      const header = injectedHeaderOf(point.payload);
      if (header === null) return { outcome: 'unavailable', error: 'payload carries no injected header' };

      let injectedHeaders: Headers;
      try {
        injectedHeaders = (await fetchImpl(point.url)).headers;
      } catch (err) {
        return { outcome: 'unavailable', error: `injection fetch failed: ${errorMessage(err)}` };
      }

      // The header the payload meant to inject isn't present with its nonce value:
      // reflected into the body at most, not split into a header line.
      if (injectedHeaders.get(header.name) !== header.value) return { outcome: 'not_vulnerable' };

      // The injected header is present, but only the payload proves it: if the baseline
      // already carries it, the server sends it unconditionally. A baseline we can't
      // fetch can't clear that doubt, so we can't confirm.
      let baselineHeaders: Headers;
      try {
        baselineHeaders = (await fetchImpl(crlfBaselineUrlFor(point))).headers;
      } catch (err) {
        return { outcome: 'unavailable', error: `baseline fetch failed: ${errorMessage(err)}` };
      }
      if (baselineHeaders.get(header.name) === header.value) return { outcome: 'not_vulnerable' };

      return { outcome: 'confirmed', evidenceSnippet: `${header.name}: ${header.value}` };
    },
  };
}

// The default CRLF class, backed by the SSRF-guarded content fetcher.
export const crlfInjectionClass: InjectionClass = makeCrlfInjectionClass();
