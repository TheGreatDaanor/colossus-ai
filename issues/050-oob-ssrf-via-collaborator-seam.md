---
id: 050
title: Confirm OOB SSRF end-to-end through the CollaboratorClient seam
status: open
type: afk
blocked-by: [049]
---

## Slice

An active-mode scan injects a unique collaborator URL into each query param and,
when a fake collaborator reports the target called back, an `ssrf` finding
(high, definitive) appears in the scan's findings — the thick tracer bullet:
new seam + new service + scanner wiring + finding, driven entirely by a fake.

## User stories covered

- From PRD: test each query param for SSRF; `ssrf` finding on OOB callback;
  confirmation within the scan; one finding per (target, param); active-mode attestation only;
  runs on all in-scope targets including discovered ones.

## Layers touched

- Schema: writes `structured_evidence` `{ kind: 'ssrf', tier: 'oob', ... }` (from 049).
- Service: NEW `src/services/ssrf-probe.ts` — `CollaboratorClient` interface +
  two-phase `SsrfProbe` (`fire(point)` registers an in-memory token; `drainCollaborator()`
  aggregates hits by token). Outcomes recorded as injection attempts (phase `oob`),
  reusing the XSS outcome model. NOT an `InjectionClass`. HTTP-scheme collaborator payload
  into every query param; body-free proof assembly; findings flow through existing
  `llmEnrichImpl` with full evidence as-is.
- Service: MODIFY `src/services/scanner.ts` — active-mode fire under `#fetchSemaphore`,
  a single scan-level ~30s drain barrier polling every ~3s, persist outcomes.
  No drain when nothing was fired; otherwise the full window, no early exit.
- Route / UI: finding surfaces in the existing findings list (polished rendering: 056).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green (fake `CollaboratorClient` + fake `BodyFetchImpl`)
- [ ] One finding per (target, param); unique-per-point tokens
- [ ] Per-point `oob` attempt rows (`confirmed` / `not_vulnerable`) tagged
      `check: 'ssrf'`; `InjectionAttempt` gains `check` (absent reads as `xss`)
- [ ] Writing SSRF attempts merges with, never overwrites, the target's XSS attempts
      (test: XSS + SSRF on one target → both sets present)
- [ ] No token fired → no drain wait
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active scan whose fake collaborator reports a token hit → `ssrf`
      finding in that scan's findings

## Out of scope

- DNS capture / DNS+HTTP dedup (051)
- Response-based internal-read critical tier (052)
- Unavailable outcomes and the preflight self-test / own-egress filter (053)
- Newness keying (054)
- The real listener daemon (055) — this slice uses a fake CollaboratorClient
- Non-http schemes; body/header injection points
