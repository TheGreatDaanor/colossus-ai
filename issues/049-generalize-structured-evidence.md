---
id: 049
title: Generalize finding evidence to a discriminated structured_evidence column
status: in-review
type: human
blocked-by: []
---

## Slice

Existing IDOR / unauthenticated-resource-access findings still render their exact
differential proof, now read from a single `structured_evidence` column instead of
`access_control_evidence`, with every shipped row retrofitted — the refactor that
gives the SSRF finding a proof lane to write into.

<!-- Justified exception: this is a pure refactor that unblocks the first real SSRF
slice (050). It is human because it moves shipped Phase-5 data. The destructive
drop is split out into 057. -->

## User stories covered

- From PRD: an SSRF (and access-control) finding carries body-free structured proof.
- From PRD data model: fold `access_control_evidence` into a discriminated
  `structured_evidence`; retrofit existing rows.

## Layers touched

- Schema: add `findings.structured_evidence` (text, nullable) via a generated
  migration; keep `access_control_evidence`, no longer written or read (dropped in
  057). `evidence_path` / `evidence_snippet` untouched.
- Service: access-control write/read path uses `structured_evidence` with variant
  `{ kind: 'access-control', ... }`.
- Route / UI: existing findings list keeps rendering access-control proof unchanged.
- Data: `createDb` runs migrations in one pass at startup, so an outside script
  can't run between the add and the drop. Instead an idempotent copy runs right
  after `migrate()`: each row with `access_control_evidence` and no
  `structured_evidence` gets it tagged as `{ kind: 'access-control', ... }`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] Startup copy migrates existing rows deterministically and idempotently;
      verified on a seeded db
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `npm run dev` → an existing IDOR finding shows its differential proof

## Out of scope

- Dropping `access_control_evidence` and removing the startup copy (057)
- SSRF variant of `structured_evidence` (added in 050)
- Folding `evidence_path` / `evidence_snippet` in — they are a file pointer and a
  raw substring, not structured proof
