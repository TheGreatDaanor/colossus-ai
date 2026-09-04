---
id: 016
title: Report insecure cookie flags per cookie, naming the missing attribute
status: done
type: afk
blocked-by: []
---

## Slice

A target that sets several cookies produces one finding *per* offending
cookie, each naming the cookie and the specific attribute it lacks, instead
of today's single `insecure-cookie` finding derived from whichever
`Set-Cookie` header survived being collapsed into a `Record<string,string>`.

## Why this is a bug, not an enhancement

`lowercaseHeaders` builds a `Record<string, string>`, so a response with
five `Set-Cookie` headers keeps one value. `detectHeaderFindings` then reads
`headers['set-cookie']` — meaning an insecure session cookie sitting
alongside a secure one is silently missed. `isCookieSecure` additionally
ANDs Secure/HttpOnly/SameSite into one boolean, so the operator is told
"insecure" without being told which attribute is absent, on which cookie.

## User stories covered

- From PRD: as the operator, I can see which security response headers are
  missing on each target, so I know about clickjacking/MIME-sniffing/HSTS/
  cookie risks — currently only satisfied for one arbitrary cookie.

## Layers touched

- Service: `src/services/scanner.ts` — capture all `Set-Cookie` values via
  `Headers.getSetCookie()` and carry them alongside the flattened header
  record; replace `isCookieSecure`'s boolean with per-attribute detection.
- Schema: none. Each finding is an ordinary `findings` row.

## Categories emitted

Flat siblings, one per distinct defect (see [[CONTEXT]] — finding category):

- `cookie-missing-secure`
- `cookie-missing-httponly`
- `cookie-missing-samesite`

All `severity: medium`, `confidence: definitive` — attribute absence is a
fact about the response.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a stubbed fetch returning three `Set-Cookie` headers (one
      fully secure, two each missing a different attribute) yields exactly
      two findings naming the right cookies and attributes; `curl
      localhost:PORT/scans/:id` shows them.

## Out of scope

- Cookie *value* analysis (entropy, JWT decoding, PII sniffing).
- `__Host-`/`__Secure-` prefix validation.
- Changing the `insecure-cookie` category on already-stored findings — old
  rows keep their category; only new scans use the new ones.

## Sequencing note

This lands **before** [[017]]'s extraction on purpose: fix the bug against
the tests where the code currently lives, then move it, so the refactor
stays a behavior-free diff.
