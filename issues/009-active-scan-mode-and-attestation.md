---
id: 009
title: Add active scan mode with required attestation gate
status: done
type: afk
blocked-by: []
---

## Slice

`POST /scans` accepts `mode: "active"` and, when present, requires
`confirmAuthorized: true` or rejects the request before any target is
touched — visible as a 400-class response with an explanatory error when
`mode: "active"` is submitted without attestation, and a scan record
carrying `mode`/`confirmAuthorized`/`authorizationNote` when it is.

## User stories covered

- From PRD: I can opt a scan into active mode.
- From PRD: I must explicitly attest I'm authorized to actively test these
  targets.

## Layers touched

- Schema: `scans` table — add `mode` (`passive`|`active`, default
  `passive`), `confirm_authorized` (boolean, nullable), `authorization_note`
  (text, nullable).
- Service: `src/services/scanner.ts` — `startScan` validates
  `mode`/`confirmAuthorized` and persists them; no active-scanning behavior
  yet (that's [[010]]/[[011]]), only the gate and the field plumbing.
- Route: `src/routes/scans.ts` — passes the new fields through, surfaces the
  validation error as a client error response.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `curl -X POST localhost:PORT/scans -d '{"urls":["https://example.com"],"mode":"active"}'` is rejected; the same request with `"confirmAuthorized": true` added is accepted and `GET /scans/:id` shows `mode: "active"`.

## Out of scope

- Actually performing any active check — targets in active mode behave
  exactly like passive mode until [[010]] and [[011]] land.
