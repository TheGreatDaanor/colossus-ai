---
id: 054
title: Mark repeat SSRF findings not-new via the existing diff machinery
status: open
type: afk
blocked-by: [050]
---

## Slice

Re-scanning a target that still has a standing SSRF shows the finding as not-new in
the inventory diff view, keyed on `(target, param, category, tier)` rather than
the ephemeral token — so a tier upgrade (`oob` → `internal-read`) is new.

## User stories covered

- From PRD: fresh scan fires fresh; an SSRF matching a prior scan is recorded but
  marked not-new via the existing newness source of truth (issues 041 / 039); a
  tier upgrade is new.

## Layers touched

- Schema: none new (reuses newness source-of-truth).
- Service: `ssrf` findings participate in the existing newness keying on
  `(target, param, category, tier)`; never keyed on the token.
- Route / UI: existing inventory diff view shows the finding as not-new.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] First scan: ssrf new; re-scan with same standing bug: ssrf not-new
- [ ] Re-scan where the same param now reads metadata (oob → internal-read): new
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: re-scan of a target with a standing SSRF → finding shows not-new in diff

## Out of scope

- Cross-scan dedup/suppression (findings are still recorded per scan)
