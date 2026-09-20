---
id: 044
title: Deepen LFI to catch Windows targets via a win.ini traversal
status: done
type: afk
blocked-by: []
---

## Slice

The LFI class stops reading Windows hosts as clean: alongside the existing
`/etc/passwd` traversal it injects a `..\..\..\windows\win.ini` traversal
and confirms on a Windows-file signature (`[fonts]`/`[extensions]`). An
operator scanning a Windows/IIS target vulnerable to path traversal now
gets a confirmed `lfi` finding via `GET /scans/:id`.

## User stories covered

- From PRD: "LFI catches Windows targets, not just Unix, so a vulnerable
  IIS/Windows host doesn't read clean."

## Layers touched

- Service: `src/services/active-scanner.ts` — the LFI class enumerates a
  Windows `win.ini` traversal in addition to `/etc/passwd`, and its
  confirmer matches the `[fonts]`/`[extensions]` signature, cleared against
  the baseline. No new category — a Windows hit is still `lfi`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass — includes a baseline-present
  case proving the differential still clears a page that shows the signature
  unconditionally
- [ ] Visible at: an active-mode scan of a Windows-file-traversal-vulnerable
  target records a confirmed `lfi` finding with the `win.ini` signature in
  `evidence_snippet`, via `GET /scans/:id`.

## Out of scope

- `php://filter` and other PHP-wrapper LFI — no clean deterministic string
  signature (see PRD out-of-scope).
- New `FindingCategory` values — a Windows hit stays `lfi`.
- CRLF ([[043]]) and SQLi ([[045]]) work.
