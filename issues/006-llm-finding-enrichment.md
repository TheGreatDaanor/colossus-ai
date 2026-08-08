---
id: 006
title: Enrich findings with LLM-generated explanation and suggested fix
status: open
type: afk
blocked-by: [001]
---

## Slice

Every Finding returned by `GET /scans/:id` now carries a plain-English
`explanation` and `suggested_fix`, produced via a structured (tool-use) call
to Claude. Identical finding-sets within one scan reuse a single LLM call
instead of one call per finding.

Tests seed fixture Finding rows directly (no dependency on [[003]]/[[004]]/[[005]]
actually producing findings — the enrichment step operates on whatever
findings exist, regardless of which detector made them).

## User stories covered

- From PRD: get a plain-English explanation and suggested fix for every
  finding — `explanation`/`suggested_fix` via structured tool-use output, not
  free text.
- From PRD: don't pay for redundant LLM work within one scan — explanations
  cached per finding-set fingerprint within a scan, not across scans.
- From PRD: when the LLM step fails but detection succeeded, still get raw
  findings — retries once, then degrades to `null` explanation/fix without
  failing the target or scan.

## Layers touched

- Service: `src/services/scanner.ts` — add `@anthropic-ai/sdk` as a
  dependency; `enrichFindings` step using structured tool-use output;
  fingerprint-based dedup cache scoped to the scan; retry-once-then-degrade
  on failure. The Anthropic call is a mockable seam (tests never call the
  real API).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: test seeds a scan with fixture Finding rows, mocks the
      Anthropic call, and `curl localhost:PORT/scans/:id` shows
      `explanation`/`suggested_fix` populated — same text renders in the
      findings sub-table on the dashboard ([[001]]); a second identical
      finding-set in the same scan doesn't trigger a second LLM call
      (assert via mock call count).

## Out of scope

- Prompt-injection hardening against attacker-controlled scanned content —
  accepted risk per the PRD; raw findings are always shown regardless of LLM
  output.
