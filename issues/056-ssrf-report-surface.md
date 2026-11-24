---
id: 056
title: Render SSRF evidence and a not-tested indicator on the report
status: open
type: human
blocked-by: [050, 053]
---

## Slice

An operator reading a scan report sees an `ssrf` finding's proof as labeled fields
(param, protocols, caller egress IP, tier, matched signature, and "metadata read:
not demonstrated" when `internalRead` says so) rather than raw JSON,
and sees an explicit "SSRF: not tested (<reason>)" indicator — per parameter,
from the `unavailable` attempts — when that outcome fired — so a clean report is never mistaken for "no SSRF."

<!-- human: visual/taste surface. -->

## User stories covered

- From PRD: SSRF finding never shows a response body; not-tested indicator on the
  report for the unavailable outcome.

## Layers touched

- Schema: none.
- Service: none new (reads `structured_evidence` and the `unavailable` attempts with their reasons).
- Route / UI: findings surface renders the `ssrf` variant as labeled fields; scan
  report shows the not-tested indicator when SSRF was `unavailable`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] ssrf proof rendered as labeled fields, no raw body; not-tested indicator shows on unavailable
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `npm run dev` → an `ssrf` finding shows labeled proof; an
      unavailable scan shows the not-tested indicator

## Out of scope

- Bespoke SSRF dashboards beyond the existing findings list + report
