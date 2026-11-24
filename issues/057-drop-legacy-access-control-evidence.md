---
id: 057
title: Drop the legacy access_control_evidence column and its startup copy
status: open
type: human
blocked-by: [049]
---

## Slice

Step 2 of the `structured_evidence` move. Once every deployment has started at
least once on 049 (so its startup copy has run), drop `access_control_evidence`
and delete the copy. Afterwards the schema has a single proof column.

<!-- human: destructive. Run only after confirming every deployment has started on
049; a deployment that skips straight here loses its Phase-5 proof. -->

## User stories covered

- From PRD data model: fold `access_control_evidence` into `structured_evidence`
  (step 2 of 2).

## Layers touched

- Schema: remove `accessControlEvidence` from `schema.ts`; `drizzle-kit generate`
  produces the drop migration (never hand-written).
- Service: delete `carryLegacyAccessControlEvidence` from `src/db/client.ts` and
  its test.
- Route / UI: none.

## Definition of done

- [ ] Confirmed every deployment has started on 049
- [ ] Generated migration drops `access_control_evidence`
- [ ] Startup copy and its test removed; no reference to the old column remains
      outside generated migrations
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an existing IDOR finding still shows its proof after the drop

## Out of scope

- Any change to `structured_evidence` variants
