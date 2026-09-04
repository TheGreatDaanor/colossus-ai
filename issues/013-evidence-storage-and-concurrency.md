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

## Layers touched

- Schema: `findings` table — add `evidence_path` column (nullable).
- Service: `src/services/active-scanner.ts` — on `confirmed`, capture a
  Playwright screenshot, write it to `data/evidence/<scan_id>/<finding
  marker>.png`, return the path.
- Service: `src/services/scanner.ts` — `#runScan` batches active-mode
  targets at a concurrency cap of 2-3, separate from the passive batch
  size.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a confirmed-XSS finding in `GET /scans/:id` includes `evidencePath`, and the file exists on disk at that path; a test asserts active-mode batching never exceeds the configured concurrency cap even when submitting more targets than the cap.

## Out of scope

- Richer evidence (video, HAR capture) — deferred per the PRD.
- A job queue for active scans — deferred per the PRD; concurrency stays an
  in-process batch cap.
