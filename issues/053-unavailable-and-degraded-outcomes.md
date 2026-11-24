---
id: 053
title: Report SSRF as unavailable when the collaborator is absent or fails
status: open
type: afk
blocked-by: [050]
---

## Slice

An active scan with no collaborator configured (or one whose self-test fails)
reports SSRF as "not tested" (`unavailable`, with a reason) while every other class
runs normally; a listener failure mid-drain marks the affected attempts
`unavailable` rather than reporting a clean bill; and callbacks from Colossus's own
egress are discarded.

## User stories covered

- From PRD: collaborator unavailable/unconfigured → `unavailable`, never
  "not vulnerable", never a failed scan; mid-drain listener failure → `unavailable`
  with reason (no new scan status); late callbacks dropped and logged; Colossus's
  own callbacks never confirm.

## Layers touched

- Schema: none.
- Service: scanner preflights with `CollaboratorClient.selfTest()` — Colossus fetches
  a fresh token URL itself, proving the path end-to-end and learning its own egress
  IPs; absent/failed → SSRF `unavailable` attempts up front with a reason; hits from
  own egress IPs discarded; poll failure during drain → affected attempts
  `unavailable` with reason `collaborator-unreachable-mid-drain`, scan completes; late hits (after window) dropped and logged; observability counters
  (fired vs received, late-callback, unavailable).
- Route / UI: the not-tested indicator itself lives in 056; this slice emits the outcome.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] No collaborator or failed self-test → SSRF unavailable with reason, other
      classes still run; mid-drain poll failure → unavailable with reason
- [ ] A hit from Colossus's own egress IP does not confirm
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active scan with collaborator unconfigured → scan completes,
      SSRF marked unavailable (not clean)

## Out of scope

- The not-tested report banner rendering (056)
