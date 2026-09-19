---
id: 014
title: Discover same-origin links/forms and add them as new scan targets
status: done
type: afk
blocked-by: []
---

## Slice

A scan target's fetched HTML is parsed for same-origin `<a href>` links and
`<form>` action URLs; each one not already a target on this scan is added
as a new `scan_targets` row (with `discoveredFrom` set to the source
target's id) and run through the same passive/active pipeline as any
other target — bounded by a depth-2, 25-page-per-root cap — visible as
`GET /scans/:id` returning more targets than the operator originally
submitted, each traceable back to the page it was found on.

## User stories covered

- From PRD: submitting one URL gets me findings across the pages linked
  from it.
- From PRD: discovery never leaves the origin I submitted (subdomains,
  other ports/schemes excluded).
- From PRD: discovery has a hard ceiling (25 pages, depth-2, per root
  target).
- From PRD: discovery runs whether or not I opted into active scanning
  (no `mode` gate on discovery itself).
- From PRD: I can see how a discovered target was found (`discoveredFrom`).

## Layers touched

- Schema: `scan_targets` — add `discovered_from` (integer, nullable,
  self-referencing FK to `scan_targets.id`).
- Service: `src/services/discovery.ts` (new) —
  `discoverLinks(page: { url: URL; html: string }): string[]`, pure
  same-origin filtering of `<a href>`/`<form action>` URLs found in the
  given HTML. No robots.txt filtering yet (that's [[015]]).
- Service: `src/services/scanner.ts` — after a target's passive fetch
  completes, calls `discoverLinks`, inserts new same-origin URLs as
  `scan_targets` rows with `discoveredFrom` set, and feeds them through
  the existing per-target pipeline; enforces the 25-page/depth-2 cap by
  walking `discoveredFrom` back to the root and counting discovered rows
  per root.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an active- or passive-mode scan against a fixture page containing same-origin links produces additional `scan_targets` rows in `GET /scans/:id`, each with `discoveredFrom` pointing back to the submitting target; a fixture with more same-origin links than the cap allows produces exactly 25 discovered targets, and none deeper than 2 hops from the root.

## Out of scope

- `robots.txt`-based filtering of discovered links — [[015]].
- Cross-origin links, subdomains, other ports/schemes — never followed,
  per the PRD's authorization-boundary reasoning.
- Configurable cap/depth — fixed at 25/depth-2 for this phase.
- Any exploitation of discovered targets beyond what the existing
  passive/active pipeline already does — no new vulnerability-class logic
  here.
