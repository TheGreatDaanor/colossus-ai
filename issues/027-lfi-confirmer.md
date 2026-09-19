---
id: 027
title: Confirm local file inclusion via an /etc/passwd signature oracle
status: done
type: afk
blocked-by: [023, 024]
---

## Slice

An LFI `InjectionClass` injects a path traversal to a known-content file
into each query parameter and confirms a finding iff a stable file
signature appears in the response — visible as a confirmed `lfi` finding
(severity high, confidence definitive) with the matched line in
`evidence_snippet`.

## User stories covered

- From PRD-injection-classes: "I get ... LFI confirmed alongside XSS", and
  "each confirmed non-XSS finding shows me the response evidence that
  proved it".

## Layers touched

- Service: `src/services/active-scanner.ts` — an `lfi` implementation of
  `InjectionClass`. `enumerate` mutates each query param with a traversal
  payload (`../../../../etc/passwd`). `confirm` fetches baseline + injected
  responses through the SSRF-guarded fetch path; confirms iff the signature
  `root:.*:0:0:` appears in the injected response and was absent from the
  baseline. Captures the matched line for `evidence_snippet`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active-mode scan of a target that returns `/etc/passwd`
  content on the traversal payload records a confirmed `lfi` finding with
  the matched line in `evidence_snippet`; a target that returns the param
  echoed or a 404 records no finding.

## Out of scope

- Wiring the class into the scanner's per-target run + concurrency ([[028]]).
- Windows-path traversal and non-`/etc/passwd` targets.
- PHP wrapper / filter chains, log poisoning, RCE escalation.
