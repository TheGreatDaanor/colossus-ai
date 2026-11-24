---
id: 058
title: Bound the finding-newness lookup with a normalized, indexed target key
status: open
type: afk
blocked-by: [054]
---

## Slice

An operator opening a scan report (`GET /scans/:id` or `/dashboard/scans/:id`)
gets it back in roughly constant time however many scans have run before,
because finding newness reads only the earlier findings for *this scan's
targets*, not the whole history.

## Background

Newness (054) marks a finding new unless an earlier scan recorded the same
defect. Today `findingsBeforeScan` (`src/db/finding-history.ts`) reads every
finding from every earlier scan on each read, so report latency grows with the
history. It cannot filter in SQL by URL: `scan_targets.url` is stored as typed,
and identity matches targets by their normalized form (`sameTargetKey`, i.e.
`new URL(raw).href`), so `https://example.com` and `https://example.com/` are
the same target. Found in the review of PR #25 (finding 9).

## User stories covered

- From PRD: finding newness across scans (054), at a scale of months of scans.

## Layers touched

- Schema: add a `target_key` column on `scan_targets` (the `sameTargetKey`
  form), indexed with `scan_id`. Generate the migration with drizzle-kit; never
  hand-edit `src/db/migrations/`. Backfill existing rows at startup, the way
  `carryLegacyAccessControlEvidence` does in `src/db/client.ts`.
- Service: write `target_key` on every scan-target insert (submitted,
  inventory, crawl-discovered, invalid). `findingsBeforeScan` takes this scan's
  target keys and filters `target_key IN (...) AND scan_id < ?`.
- Route / UI: none.

## Definition of done

- [ ] Failing test written first, confirmed red: a re-scan spelled
      `https://example.com` vs `https://example.com/` still marks the standing
      finding not-new, and the lookup only returns rows for the scan's targets
- [ ] Implementation makes it green
- [ ] Existing newness tests (054, the per-cookie test) still pass
- [ ] Rows written before the migration are backfilled and still match
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `npm run dev` → a scan report on a database with many earlier
      scans loads without reading their findings (check with a query log or timing)

## Out of scope

- Storing a precomputed finding identity column (cookie name, SSRF tier, …).
  Revisit only if the per-target lookup is still slow.
- Changing what counts as the same defect.
