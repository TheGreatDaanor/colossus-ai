---
id: 025
title: Confirm server-side template injection via an arithmetic oracle
status: open
type: afk
blocked-by: [023, 024]
---

## Slice

An SSTI `InjectionClass` injects a unique arithmetic expression into each
query parameter and confirms a finding iff the template engine evaluated
it — visible as a confirmed `ssti` finding (severity high, confidence
definitive) with the computed product captured in `evidence_snippet`, on
an active-mode scan of an SSTI-vulnerable target.

## User stories covered

- From PRD-injection-classes: "I get SSTI ... confirmed alongside XSS",
  and "each confirmed non-XSS finding shows me the response evidence that
  proved it".

## Layers touched

- Service: `src/services/active-scanner.ts` — an `ssti` implementation of
  `InjectionClass`. `enumerate` mutates each query param with a payload
  carrying two random factors (e.g. `${{a*b}}`-style, unique per attempt).
  `confirm` fetches a baseline (unmodified) response and the injected
  response through the SSRF-guarded fetch path; confirms iff the product
  `a*b` appears in the injected response and the literal expression does
  not. Captures the matched snippet + surrounding context for
  `evidence_snippet`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active-mode scan of a target that reflects the evaluated
  product records a confirmed `ssti` finding with the product in
  `evidence_snippet`, via `GET /scans/:id`; a target that echoes the
  literal expression unchanged records no finding.

## Out of scope

- Wiring the class into the scanner's per-target run + concurrency ([[028]]).
- Non-arithmetic SSTI oracles, engine fingerprinting, or RCE escalation.
- Timing/blind confirmation.
