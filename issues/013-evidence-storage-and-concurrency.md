---
id: 013
title: Capture evidence screenshot and cap active-scan concurrency
status: open
type: afk
blocked-by: [012]
---

## Slice

A confirmed finding carries a screenshot as proof, and active-mode targets
run at a lower, independent concurrency cap than passive targets — visible
as an `evidencePath` on confirmed findings pointing to a saved screenshot
under `data/evidence/`, and an active scan against several targets never
running more than 2-3 Playwright browser contexts concurrently.

## User stories covered

- From PRD: I get a screenshot as evidence for every confirmed finding.
- From PRD: active scanning doesn't exhaust my machine.

## Concurrency: a semaphore, not a second batch size

`#runScan` batches *targets* at `#concurrency` (default 10) and active
injection runs inside `#processTarget`. So a browser cap cannot be expressed
as another batch size — ten targets in flight each wanting a browser is ten
browser contexts.

The cap is a semaphore around **browser acquisition**, independent of the
target batch loop: at most 2-3 contexts alive at once, while passive work on
the same scan continues at full width. Dropping the whole target batch to 2-3
in active mode would also work and is much simpler, but it slows every passive
check on an active scan for no reason.

A two-phase split (all passive at 10, then browser confirmation in a second
pass at 2-3) is cleaner still and would make evidence capture batchable, but
it restructures `#runScan` well beyond this slice.

## Evidence retention and naming

- Written and **never deleted**. Evidence you auto-delete is evidence you do
  not have when you need it, and the volume is bounded by confirmed findings,
  which are rare by construction. Retention is the operator's problem, stated
  here deliberately rather than left unexamined.
- `data/` is already gitignored in full, so no new ignore rule is needed.
- The on-disk filename is the **finding id**, not the payload marker. The
  marker is a UUID this codebase generated today, but naming files after
  attacker-adjacent strings is a habit that eventually meets a payload that
  did not come from us.
- Not stored as a blob on the `findings` row: that would put binary in the
  path of every `GET /scans/:id`.

## This is not [[022]]'s budget

[[022]] is blocked on a *request fan-out* budget — several extra GETs per
target, in passive mode, multiplied by the existing concurrency of 10. The cap
here is a browser-context cap in active mode. Different resource, different
issue; [[022]] defines its own.

## Layers touched

- Schema: `findings` table — add `evidence_path` column (nullable).
- Service: `src/services/active-scanner.ts` — on `confirmed`, capture a
  Playwright screenshot, write it to `data/evidence/<scan_id>/<finding
  id>.png`, return the path.
- Service: `src/services/scanner.ts` — a semaphore bounding concurrent
  browser contexts at 2-3, independent of the target batch size.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a confirmed-XSS finding in `GET /scans/:id` includes `evidencePath`, and the file exists on disk at that path; a test asserts active-mode batching never exceeds the configured concurrency cap even when submitting more targets than the cap.

## Out of scope

- Richer evidence (video, HAR capture) — deferred per the PRD.
- A job queue for active scans — deferred per the PRD; concurrency stays an
  in-process batch cap.
