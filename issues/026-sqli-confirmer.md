---
id: 026
title: Confirm error-based SQL injection via a DB-error-signature oracle
status: done
type: afk
blocked-by: [023, 024]
---

## Slice

A SQLi `InjectionClass` injects a syntax-breaking token into each query
parameter and confirms a finding iff a known DB error signature appears
that was absent from the baseline response — visible as a confirmed `sqli`
finding (severity high, confidence definitive) with the matched error line
in `evidence_snippet`.

## User stories covered

- From PRD-injection-classes: "I get ... SQLi ... confirmed alongside
  XSS", and "each confirmed non-XSS finding shows me the response evidence
  that proved it".

## Layers touched

- Service: `src/services/active-scanner.ts` — a `sqli` implementation of
  `InjectionClass`. `enumerate` mutates each query param with a
  syntax-breaking token (`'`). `confirm` fetches baseline + injected
  responses through the SSRF-guarded fetch path; confirms iff a known DB
  error signature (`SQL syntax`, `ORA-\d`, `PG::`, `SQLITE_ERROR`, and a
  small documented set) appears in the injected response and was **absent**
  from the baseline. Captures the matched error line for `evidence_snippet`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active-mode scan of a target that emits a DB error on the
  injected token records a confirmed `sqli` finding with the error line in
  `evidence_snippet`; a target whose baseline already contains that string
  records no finding (differential holds).

## Out of scope

- Wiring the class into the scanner's per-target run + concurrency ([[028]]).
- Blind / boolean / timing-based SQLi (no deterministic oracle).
- Data extraction or exploitation beyond confirmation.
