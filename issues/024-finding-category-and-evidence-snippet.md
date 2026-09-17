---
id: 024
title: Add SSTI/SQLi/LFI finding categories and an evidence_snippet column
status: open
type: afk
blocked-by: []
---

## Slice

`FindingCategory` gains `'ssti' | 'sqli' | 'lfi'` and `findings` gains a
nullable `evidence_snippet` text column, so oracle-confirmed classes have
somewhere to record their category and the response substring that proved
them — visible as the new column present in the generated migration and
selectable via `GET /scans/:id`.

## User stories covered

- From PRD-injection-classes: "each confirmed non-XSS finding shows me the
  response evidence that proved it" — the storage half of that story
  (`evidence_snippet` column + new categories). Populating it is each
  class's own issue.

## Layers touched

- Schema: `src/db/schema.ts` — extend `FindingCategory` type union with
  `'ssti' | 'sqli' | 'lfi'`; add `evidenceSnippet: text('evidence_snippet')`
  (nullable) to `findings`.
- Migration: generate via drizzle (never hand-edit `src/db/migrations/`).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a finding row can be written with `category: "ssti"` and
  a non-null `evidence_snippet`, and it round-trips through
  `GET /scans/:id`.

## Out of scope

- Any confirmer that produces these categories ([[025]], [[026]], [[027]]).
- `evidence_path` behavior — unchanged, stays the XSS screenshot channel.
