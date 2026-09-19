---
id: 034
title: Flag wildcard DNS so the inventory stays trustworthy
status: open
type: afk
blocked-by: [032]
---

## Slice

An operator enumerating an apex with wildcard DNS sees it flagged as such, and
does not see the inventory filled with hosts that only "exist" because
everything resolves.

## User stories covered

- From PRD: wildcard DNS does not fill my inventory with fictitious hosts.

## Layers touched

- Schema: `enumerated_hosts.is_wildcard`.
- Service: `src/services/enumeration.ts` — resolve a random nonce label under
  the apex; if it resolves, flag the apex wildcard and suppress unresolved
  inferred hosts under it. A wildcard CT entry (`*.example.com`) is recorded
  as a host with `is_wildcard` set.
- Route / UI: the inventory listing marks wildcard hosts.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `GET /programs/:id/hosts` against a stubbed wildcard apex
      shows the wildcard entry flagged and no fictitious hosts listed.

## Out of scope

- Wordlist brute-force, which is where wildcards bite hardest — deferred per
  PRD, but the flag is built now because the brute-force phase will need it.
- Scanning wildcard entries — they are never scanned.
