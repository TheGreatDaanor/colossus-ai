---
id: 049
title: Generalize finding evidence to a discriminated structured_evidence column
status: open
type: human
blocked-by: []
---

## Slice

Existing IDOR / unauthenticated-resource-access findings still render their exact
differential proof, now read from a single `structured_evidence` column instead of
`access_control_evidence`, with every shipped row retrofitted — the refactor that
gives the SSRF finding a proof lane to write into.

<!-- Justified exception: this is a pure refactor + destructive migration that
unblocks the first real SSRF slice (050). It is human because it drops a column and
backfills shipped Phase-5 data. -->

## User stories covered

- From PRD: an SSRF (and access-control) finding carries body-free structured proof.
- From PRD data model: fold `access_control_evidence` into a discriminated
  `structured_evidence`; retrofit existing rows.

## Layers touched

- Schema: add `findings.structured_evidence` (text, nullable); drop
  `access_control_evidence`. `evidence_path` / `evidence_snippet` untouched.
- Service: access-control write/read path uses `structured_evidence` with variant
  `{ kind: 'access-control', ... }`.
- Route / UI: existing findings list keeps rendering access-control proof unchanged.
- Data: one-shot backfill script (OUTSIDE `src/db/migrations/`, which is generated
  and off-limits) copies each non-null `access_control_evidence` into
  `structured_evidence` wrapped as `{ kind: 'access-control', ... }` before the drop.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] Backfill script migrates existing rows deterministically; verified on a seeded db
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `npm run dev` → an existing IDOR finding shows its differential proof

## Out of scope

- SSRF variant of `structured_evidence` (added in 050)
- Folding `evidence_path` / `evidence_snippet` in — they are a file pointer and a
  raw substring, not structured proof
