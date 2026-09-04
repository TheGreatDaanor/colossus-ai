---
id: 011
title: Confirm XSS execution via Playwright and emit findings
status: open
type: afk
blocked-by: [010]
---

## Slice

Each canary-injected URL from [[010]] is loaded in a headless Playwright
browser; if the marker executes, a `findings` row is created with
`category: "xss"`, `severity: "high"`, `confidence: "definitive"`, and the
injection point/payload recorded — visible as a real finding in
`GET /scans/:id` for a target actually confirmed vulnerable, and a
distinct, visible `not_vulnerable`/`unavailable` outcome (no finding) for
targets that aren't.

## User stories covered

- From PRD: I can see which of my target URLs have a confirmed,
  browser-verified reflected XSS.
- From PRD: I can tell "not vulnerable" apart from "we couldn't test it".

## Marker detection (decided)

Execution is detected by reading the `window.__colossus_xss_marker` property
via `page.evaluate`, matched against the UUID in the attempt's payload. This
is not left to the implementation: [[010]] already committed the payload shape
(`<script>window.__colossus_xss_marker='<uuid>'</script>`) in
`generateCanaryPayload`, so a dialog-based marker would mean reopening it.

A `window`-property marker misses reflections that execute but cannot set a
global (inside a closure, some CSP'd contexts). Catching those needs a
*different payload shape*, which is a later injection-point issue, not this
one.

## Where the outcome is stored

`scan_targets.injection_attempts` already exists as a JSON column. Widen its
`InjectionAttempt` type to `{ injectionPoint, payload, outcome, error? }`
rather than adding a table or a scalar column — attempts are written in one
shot per target, so this costs no migration and keeps attempt data in one
place. A separate `injection_attempts` table would only earn its keep if
attempts needed querying across targets, which nothing on the roadmap asks
for.

## Retry and timeout policy

- Retry once on browser **launch** failure only — a launch failure is
  infrastructure and usually transient.
- Do **not** retry a failed navigation: it will fail again, and retrying
  doubles the time a hostile target can hold a browser context.
- Explicit navigation timeout (~10s) plus a total per-attempt budget.
- A navigation timeout is `unavailable`, never `not_vulnerable`. These must
  not collapse — telling them apart is the PRD user story this issue
  satisfies.

## Test fixtures and the SSRF guard

The DoD's fixture page is served by a real local HTTP server started in the
test (`http.createServer` on an ephemeral port), not by `page.route()` and not
by a `data:` URL. [[012]] uses `page.route()` as production behavior; if the
test owns that hook too, the test and the code under test fight over it. A
real loopback server also gives [[012]] somewhere to serve a real redirect to
a private address from.

This means the SSRF guard must not reject the test's own server: the scanner
gains an `allowedHosts: string[]` constructor option, defaulting to empty, set
only by tests. Deliberately a constructor option and not an environment
variable — an env var that disables an SSRF guard is a production incident
waiting to happen.

## Layers touched

- Dependency: add `playwright`, Chromium only, via
  `RUN npx playwright install --with-deps chromium` at the marked project
  toolchain line in `scripts/Dockerfile`. Pinning the browser to the npm
  dependency (rather than switching to a Playwright base image) keeps the
  uid/gid and `/home/agent/.claude` handling already worked out there.
- Schema: `findings` table — add `injection_point`, `payload` columns
  (nullable). `scan_targets.injection_attempts` — widen the JSON type as
  above; no migration.
- Service: `src/services/active-scanner.ts` —
  `confirmXss(url): Promise<XssAttemptResult>` launches a Playwright page,
  navigates to the canary URL, detects marker execution as above, resolves to
  `confirmed` | `not_vulnerable` | `unavailable`.
- Service: `src/services/scanner.ts` — on `confirmed`, writes a `findings`
  row; on any outcome, records the outcome on the target's stored attempt
  (not silently dropped).
- Tests: real Chromium in the fixture test only; `confirmXss` is mocked at its
  boundary everywhere else.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an active-mode scan against a locally-served fixture page that reflects the query param unescaped produces a `findings` row with `category: "xss"`, `confidence: "definitive"`; the same scan against a fixture that escapes the param produces no finding but a visible `not_vulnerable` outcome on the target.

## Out of scope

- Screenshot/evidence capture — [[013]].
- SSRF guard during in-browser navigation — [[012]].
- Any payload beyond a harmless canary marker.
