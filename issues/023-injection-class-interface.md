---
id: 023
title: Extract an InjectionClass interface with XSS as its first implementation
status: done
type: afk
blocked-by: []
---

## Slice

`active-scanner.ts` exposes an `InjectionClass` strategy interface
(`category`, `enumerate`, `confirm`) and the existing reflected-XSS logic
is refactored to be its first implementation, behind that interface — a
pure refactor with no behavior change, visible as an unchanged active-mode
XSS scan still producing the same confirmed finding + screenshot.

## User stories covered

- Infrastructure for: from PRD-injection-classes, "when I run an active
  scan I get SSTI, SQLi, and LFI confirmed alongside XSS" — this issue
  creates the seam the three new classes plug into; no new class ships
  here.

## Layers touched

- Service: `src/services/active-scanner.ts` — define
  `interface InjectionClass { category: FindingCategory;
  enumerate(target: URL): InjectionPoint[];
  confirm(point: InjectionPoint): Promise<...> }`; move
  `enumerateInjectionPoints` and `confirmXss` (with its Playwright
  lifecycle intact) behind an `xssInjectionClass` implementation.
- Service: `src/services/scanner.ts` — call the XSS class through the
  interface rather than the standalone functions.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an active-mode scan of a target with a reflected-XSS
  query param still records the same confirmed `xss` finding with a
  screenshot, via `GET /scans/:id` — behavior identical to before.

## Out of scope

- Any new injection class — SSTI ([[025]]), SQLi ([[026]]), LFI ([[027]]).
- Schema changes ([[024]]).
- Changing XSS confirmation behavior in any way — this is a refactor.
