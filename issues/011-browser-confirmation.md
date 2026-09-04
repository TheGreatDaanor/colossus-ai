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

## Layers touched

- Schema: `findings` table — add `injection_point`, `payload` columns
  (nullable).
- Service: `src/services/active-scanner.ts` — `confirmXss(url): Promise<XssAttemptResult>`
  launches a Playwright page, navigates to the canary URL, detects marker
  execution (e.g. via `page.on('dialog')` for an `alert()`-style marker, or
  a `page.evaluate` check for a `window` property marker), resolves to
  `confirmed` | `not_vulnerable` | `unavailable` (browser launch/navigation
  failure — retried once).
- Service: `src/services/scanner.ts` — on `confirmed`, writes a `findings`
  row; on any outcome, records the outcome visibly on the scan target
  (not silently dropped).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an active-mode scan against a locally-served fixture page that reflects the query param unescaped produces a `findings` row with `category: "xss"`, `confidence: "definitive"`; the same scan against a fixture that escapes the param produces no finding but a visible `not_vulnerable` outcome on the target.

## Out of scope

- Screenshot/evidence capture — [[013]].
- SSRF guard during in-browser navigation — [[012]].
- Any payload beyond a harmless canary marker.
