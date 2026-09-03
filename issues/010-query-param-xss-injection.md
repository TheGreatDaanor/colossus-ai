---
id: 010
title: Inject canary payload into query params for active-mode targets
status: open
type: afk
blocked-by: [009]
---

## Slice

For each query parameter on an active-mode target's URL, a unique canary
payload is substituted in as that parameter's value and the resulting URL
is fetched — visible as a per-target list of attempted injection points and
payloads recorded on the scan target, with no execution-confirmation yet
(that's [[011]]).

## User stories covered

- From PRD: for each query parameter on a target URL, a canary payload is
  injected as that parameter's value (injection-point selection half of
  this story; execution confirmation is [[011]]).

## Layers touched

- Service: `src/services/active-scanner.ts` (new module) — pure function(s)
  to enumerate a URL's query parameters and produce one mutated URL per
  parameter, each with a unique marker value (e.g.
  `<script>window.__colossus_xss_marker='<uuid>'</script>`); a
  `generateCanaryPayload()` helper producing a fresh unique marker per
  attempt.
- Service: `src/services/scanner.ts` — `#runScan` dispatches active-mode
  targets to `active-scanner.ts` instead of the passive fetch path.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: submitting `mode: "active"` with a target URL containing `?q=test` records an injection attempt for the `q` parameter with a unique marker payload, inspectable via `GET /scans/:id`.

## Out of scope

- URLs with no query parameters — no injection points exist, target
  produces zero attempts (not an error).
- Forms, headers, body — query params only, per the PRD.
- Actually confirming execution — [[011]].
