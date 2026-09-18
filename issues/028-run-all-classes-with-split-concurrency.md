---
id: 028
title: Run all four injection classes per active target under split concurrency
status: done
type: afk
blocked-by: [023, 025, 026, 027]
---

## Slice

`ScannerService` runs every injection class (XSS, SSTI, SQLi, LFI) against
each active-mode target's query parameters, with the fetch-based classes
sharing the passive fetch concurrency budget and XSS keeping the Playwright
browser cap — visible as a single active-mode scan of a multi-vuln target
returning confirmed findings across all four categories.

## User stories covered

- From PRD-injection-classes: "when I run an active scan I get SSTI, SQLi,
  and LFI confirmed alongside XSS" (the orchestration half), and "added
  classes don't exhaust my machine" (the concurrency story).

## Layers touched

- Service: `src/services/scanner.ts` — `#runScan` iterates all registered
  `InjectionClass` implementations per active-mode target. Fetch-based
  classes (ssti/sqli/lfi) execute under the existing passive fetch
  concurrency budget; XSS stays under the separate lower browser cap. The
  request surface is unchanged — `mode: "active"` runs all four.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: submitting `mode: "active"` (with `confirmAuthorized:
  true`) against a target vulnerable to more than one class returns a
  confirmed finding per class via `GET /scans/:id`; fetch-classes are not
  throttled by the browser cap.

## Out of scope

- Per-class selection in the request body — all four always run.
- New injection classes beyond the four.
- Changing the attestation / authorization gate.
