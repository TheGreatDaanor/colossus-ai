---
id: 040
title: Enumerate each program on a schedule
status: open
type: afk
blocked-by: [032]
---

## Slice

A program's inventory refreshes on its own, so new hosts are noticed between
scans rather than only when someone remembers to run one.

## User stories covered

- From PRD: enumeration runs on a schedule as well as on demand.

## Layers touched

- Schema: none — uses `programs.last_enumerated_at`.
- Service: a scheduler that triggers `enumerate` per program on its cadence,
  reusing the same non-fatal failure path and cache as the on-demand path.
- Route / UI: the program shows when it last enumerated, and whether the last
  attempt errored.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `GET /programs/:id` shows `last_enumerated_at` advancing
      with no scan having run; a failed scheduled run surfaces the error
      without clearing the inventory.

## Out of scope

- The scheduler's timing itself is untested per the PRD — cadence is
  configuration; the enumeration it triggers is tested directly in 032.
- Per-program configurable cadence.
