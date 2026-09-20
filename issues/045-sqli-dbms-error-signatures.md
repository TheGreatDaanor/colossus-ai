---
id: 045
title: Deepen SQLi error signatures to cover MySQL, MSSQL, and DB2
status: done
type: afk
blocked-by: []
---

## Slice

The error-based SQLi class stops reading MySQL/MSSQL/DB2 backends as clean:
`SQL_ERROR_SIGNATURES` gains signatures for those engines alongside the
existing set. An operator scanning a target with, say, a vulnerable MySQL
backend now gets a confirmed `sqli` finding via `GET /scans/:id`.

## User stories covered

- From PRD: "SQLi recognises the common database engines, so a vulnerable
  MySQL/MSSQL/DB2 backend doesn't read clean."

## Layers touched

- Service: `src/services/active-scanner.ts` — add MySQL/MariaDB, MSSQL, and
  DB2 error signatures to `SQL_ERROR_SIGNATURES`; each match must be absent
  from the baseline response to confirm. No new category — every hit is
  still `sqli`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass — one confirmation test per new
  engine signature, plus a baseline-present case proving the differential
  still clears a page that shows a signature unconditionally
- [ ] Visible at: an active-mode scan of a target returning a MySQL/MSSQL/DB2
  error on an unbalanced quote records a confirmed `sqli` finding with the
  matched error line in `evidence_snippet`, via `GET /scans/:id`.

## Out of scope

- Blind / timing-based SQLi — no deterministic oracle (see PRD out-of-scope).
- New `FindingCategory` values — every hit stays `sqli`.
- CRLF ([[043]]) and LFI ([[044]]) work.
