---
id: 036
title: Run takeover checks across a program's hosts and persist the findings
status: open
type: afk
blocked-by: [030, 032]
---

## Slice

An operator sees takeover findings for their program's in-scope hosts, stored
and listable — the point where the detection built in 030/031 meets the
inventory built in 032.

## User stories covered

- From PRD: a dangling provider reference is reported as a takeover.
- From PRD: Colossus never claims the dangling resource.

## Layers touched

- Schema: `takeover_findings`, keyed to `enumerated_hosts` rather than
  `scan_targets`, because a takeover host frequently does not resolve and so
  has no target row.
- Service: `src/services/takeover.ts` is run across a program's in-scope
  hosts; evidence is persisted with severity, confidence and remediation.
- Route / UI: list a program's takeover findings.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `GET /programs/:id/takeovers` lists findings for a program
      whose inventory contains a stubbed dangling host, including one on a
      host that does not resolve at all.

## Out of scope

- Claiming, and storing provider credentials — permanently out of scope.
- Out-of-scope and unscoped hosts are never checked.
