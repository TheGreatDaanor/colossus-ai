---
id: 032
title: Enumerate hosts from CT logs into the program inventory
status: open
type: afk
blocked-by: [029]
---

## Slice

An operator triggers enumeration on a program and sees a list of hosts found
in Certificate Transparency logs, each already classified `in_scope`,
`out_of_scope` or `unscoped`.

## User stories covered

- From PRD: hosts are enumerated from Certificate Transparency logs.
- From PRD: a CT source outage does not fail my scan.
- From PRD: hosts matching neither list are recorded but never scanned.

## Layers touched

- Schema: `enumerated_hosts` (hostname unique per program, `source`,
  `scope_status`, `first_seen_at`); `programs.enumeration_error`,
  `programs.last_enumerated_at`.
- Service: `src/services/enumeration.ts` — `enumerate(apex)` querying crt.sh,
  with response caching so an on-demand run straight after a scheduled one
  does not re-query, and a non-fatal failure path.
  `src/services/programs.ts` — `recordHosts`, classifying each host on record.
- Route: trigger enumeration for a program, and list its inventory.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `POST /programs/:id/enumerate` then
      `GET /programs/:id/hosts` lists hosts with their scope status; with the
      CT client stubbed to fail, the error is recorded on the program and the
      existing inventory is still returned.

## Out of scope

- Wildcard detection (034) and scheme probing (035).
- Spawning scan targets (037) — recording only; nothing is fetched.
- Censys and Google CT sources — a later phase per PRD.
- Tests never contact the real crt.sh endpoint.
