---
id: 048
title: Surface a stale ground-truth session as a scan error
status: open
type: afk
blocked-by: [046]
---

## Slice

When an identity's session has gone stale and its own ground-truth fetch fails
authentication, the operator sees a reported error on the scan rather than a
silent absence of findings — so they know to re-supply the identity. Colossus
never attempts to re-authenticate.

## User stories covered

- From PRD: when an identity's session is stale mid-scan, get a reported error
  rather than a silent miss.

## Layers touched

- Service: `src/services/access-control.ts` — when an owner's ground-truth
  fetch returns an authentication failure (the identity cannot retrieve its own
  declared-private URL), do not treat the URL as testable; produce an error
  outcome identifying the identity and URL instead of a finding. No
  re-authentication is attempted.
- Service: `src/services/scanner.ts` — surface that error on the scan through
  the existing scan-error reporting path.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass — a fixture where an owner's
  ground-truth fetch returns a 401/redirect surfaces a scan error naming the
  identity, and no `idor`/`unauthenticated-resource-access` finding is fabricated
  for that URL.
- [ ] Visible at: an active-mode scan with a stale identity reports the error
  via `GET /scans/:id` rather than returning silently empty.

## Out of scope

- Re-authentication or session refresh — explicitly rejected (identities are
  opaque, see PRD / ADR 0002).
- The `idor` and `unauthenticated-resource-access` oracles themselves
  ([[046]], [[047]]).
