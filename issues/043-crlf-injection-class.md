---
id: 043
title: Confirm CRLF injection via a reflected injected response header
status: open
type: afk
blocked-by: [042]
---

## Slice

Active mode gains a fifth injection class: an operator scanning a target
whose query parameter is copied unescaped into a response header now gets a
confirmed `crlf-injection` finding — proven by injecting a uniquely-named
header through a `%0d%0a`-crafted parameter and observing it reflected in
the response headers but absent from the baseline. Visible via
`GET /scans/:id` as a `high`/`definitive` finding with the reflected header
line in `evidence_snippet`.

## User stories covered

- From PRD: "when I run an active scan I get CRLF injection confirmed
  alongside XSS, SSTI, SQLi, and LFI."
- From PRD: "a confirmed CRLF finding shows me the injected header reflected
  in the response" (category `crlf-injection`, `severity: high`,
  `confidence: definitive`, reflected header in `evidence_snippet`).
- From PRD: "a CRLF finding fires only on real reflection, not on a header
  the server already sends."
- From PRD: "the new class can't become a hole in my SSRF protection."
- From PRD: "the added class doesn't exhaust my machine" (runs under the
  passive fetch budget).

## Layers touched

- Schema: `src/db/schema.ts` (+ generated migration) — `FindingCategory`
  gains `'crlf-injection'`. No new column; the reflected header reuses
  `evidence_snippet`.
- Service: `src/services/active-scanner.ts` —
  `makeCrlfInjectionClass(fetchImpl?): InjectionClass` and default
  `crlfInjectionClass`; `enumerate()` mutates each query param with a
  nonce-named CRLF header payload; `confirm()` returns `confirmed` iff the
  injected header is in the injected response's headers and absent from the
  baseline's, `not_vulnerable` otherwise, `unavailable` on fetch failure.
- Service: `src/services/scanner.ts` — register `crlfInjectionClass` in
  `#oracleClasses` so it runs under the fetch semaphore (not the browser
  cap).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an active-mode scan of a target reflecting a query param
  into a response header records a confirmed `crlf-injection` finding with a
  non-null `evidence_snippet` and null `evidence_path`, via `GET /scans/:id`.

## Out of scope

- Response-splitting (proving a split body) — the oracle only proves a
  header was injected; see the PRD's category-slug decision.
- Header/body/form injection points — query params only.
- LFI/SQLi oracle deepening ([[044]], [[045]]).
