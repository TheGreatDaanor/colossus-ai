---
id: 033
title: Require confirmation of an inferred apex before enumeration runs
status: done
type: human
blocked-by: [029]
---

## Slice

An operator who created a program from a URL sees that its apex was inferred,
and must confirm it before anything is enumerated against it.

`type: human` because this is the authorization-widening consent step — it
moves scope from one host to an entire domain, and whether the wording makes
that consequence obvious is a matter of judgement, not a test.

## User stories covered

- From PRD: I must confirm an inferred apex before enumeration runs, so that
  scope is never widened by a parser without my agreement.

## Layers touched

- Schema: none new — enforces `scope_entries.confirmed_at` from 029.
- Service: `src/services/programs.ts` — unconfirmed entries are excluded from
  the set enumeration is allowed to run against.
- Route / UI: surfaces which entries are unconfirmed and what confirming them
  authorizes, plus the confirmation action.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: creating a program from `https://example.com/x` shows
      `example.com` as unconfirmed; enumeration refuses to run until it is
      confirmed; a human has read the confirmation wording and agrees it makes
      the widening from one host to the whole domain obvious.

## Out of scope

- Entries the operator typed explicitly — those need no confirmation.
- Per-operator persistent scope — no operator identity model exists yet.
