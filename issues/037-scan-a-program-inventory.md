---
id: 037
title: Run a scan against a program's host inventory
status: open
type: afk
blocked-by: [035]
---

## Slice

An operator starts a scan on a program and sees the existing passive and
active checks run against hosts they never submitted — the payoff slice, where
enumeration finally feeds the pipeline.

## User stories covered

- From PRD: scanning is capped per scan while recording is not.
- From PRD: newly appeared hosts are scanned first.
- From PRD: enumeration runs on demand when a scan starts.

## Layers touched

- Schema: `scans.program_id` (nullable — legacy URL-only scans are unchanged),
  `scan_targets.enumerated_host_id`.
- Service: `src/services/programs.ts` — `selectHostsToScan(programId, limit)`,
  ordering hosts never scanned since first seen ahead of least-recently-scanned,
  capped at 50. `src/services/scanner.ts` — resolves targets from the
  inventory in addition to submitted URLs, and stamps `last_scanned_at`.
- Route / UI: scan results show which targets came from the inventory.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: starting a scan on a program with 60 in-scope hosts produces
      50 targets, new hosts first; a legacy scan with no `program_id` behaves
      exactly as before.

## Out of scope

- Out-of-scope and unscoped hosts are never scanned.
- Hosts with a null `endpoint_url`, or past 3 failed resolutions, spawn no
  target.
- Changing what the checks themselves do — the pipeline is reused as-is.
