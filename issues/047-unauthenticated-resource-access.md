---
id: 047
title: Report unauthenticated access to a private resource
status: done
type: afk
blocked-by: [046]
---

## Slice

An operator sees an `unauthenticated-resource-access` finding in
`GET /scans/:id` when a URL an identity declared private is retrievable with
no session at all. This adds the second branch of the oracle established in
[[046]], reusing the no-auth control request that slice already issues.

## User stories covered

- From PRD: get an `unauthenticated-resource-access` finding when a private
  resource is reachable with no session at all.
- From PRD: the no-auth request does double duty — negative control for `idor`
  and the probe for unauthenticated access.

## Layers touched

- Service: `src/services/access-control.ts` — extend the oracle in
  `runAccessControlChecks`: when the no-auth control digest matches the owner
  ground-truth digest on a declared-private URL, emit an
  `unauthenticated-resource-access` outcome. No new fetch is issued — the
  no-auth control response from [[046]] is reused.
- Service: `src/services/scanner.ts` — persist the new category (no new
  columns; `access_control_evidence` shape is unchanged).

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass — a fixture where the no-auth
  control returns the owner's ground-truth body yields exactly one
  `unauthenticated-resource-access` finding (and no `idor` for that URL), while
  a truly public resource still yields nothing.
- [x] Visible at: an active-mode scan of a URL reachable without a session
  reports an `unauthenticated-resource-access` finding via `GET /scans/:id`.

## Out of scope

- Any change to the `idor` branch or the three-way fetch machinery ([[046]]).
- Stale/failed ground-truth session handling ([[048]]).
