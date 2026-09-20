---
id: 042
title: Widen the shared BodyFetchImpl seam to return body and headers
status: done
type: afk
blocked-by: []
---

## Slice

The injection classes' shared fetch seam changes from
`(url) => Promise<string>` to `(url) => Promise<{ body: string; headers:
Headers }>`, so a confirmer can inspect response headers, not just the
body — through the one SSRF-guarded fetch chokepoint. Pure refactor, no
behavior change: existing SSTI/SQLi/LFI active scans still produce the
same confirmed findings.

<!-- Justified horizontal exception: this is a pure refactor that unblocks
the first real slice ([[043]], CRLF injection, which is the only class that
needs response headers). It ships no user-visible capability of its own; its
"visible" check is that the three existing body-based classes are unchanged. -->

## User stories covered

- Infrastructure for: from PRD-injection-classes-phase4, "a confirmed CRLF
  finding shows me the injected header reflected in the response" — this
  issue gives the confirmer access to response headers; no new class ships
  here.

## Layers touched

- Service: `src/services/active-scanner.ts` — change
  `BodyFetchImpl` to `(url) => Promise<{ body: string; headers: Headers }>`;
  update `guardedFetchText` to return both; update the SSTI/SQLi/LFI
  confirmers to read `.body` (they ignore `.headers`).
- Service: `src/services/scanner.ts` — the injected `bodyFetchImpl` returns
  the widened shape; still SSRF-guarded.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass — the updated SSTI/SQLi/LFI seam
  tests drive `{ body, headers }` and still pass
- [ ] Visible at: an active-mode scan of an SSTI/SQLi/LFI-vulnerable target
  still records the identical confirmed finding via `GET /scans/:id` —
  behavior unchanged.

## Out of scope

- The CRLF injection class itself ([[043]]) — this only widens the seam.
- Any change to LFI/SQLi oracle coverage ([[044]], [[045]]).
- Any new `FindingCategory` value or schema change.
