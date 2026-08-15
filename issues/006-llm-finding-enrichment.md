---
id: 006
title: Enrich findings with LLM-generated explanation and suggested fix
status: done
type: afk
blocked-by: [001]
---

## Slice

Every Finding returned by `GET /scans/:id` now carries a plain-English
`explanation` and `suggested_fix`, produced via a structured (tool-use) call
to Claude Sonnet 5. Identical finding-sets within one scan reuse a single
in-flight LLM call instead of one call per finding, even across concurrent
targets in the same batch. The same text renders inline on the dashboard's
findings sub-table. A missing `ANTHROPIC_API_KEY` fails the server at
startup rather than silently degrading every enrichment to null at scan time.

Tests seed fixture Finding rows directly (no dependency on [[003]]/[[004]]/[[005]]
actually producing findings — the enrichment step operates on whatever
findings exist, regardless of which detector made them).

## User stories covered

- From PRD: get a plain-English explanation and suggested fix for every
  finding — `explanation`/`suggested_fix` via structured tool-use output, not
  free text.
- From PRD: don't pay for redundant LLM work within one scan — explanations
  cached per finding-set fingerprint within a scan, not across scans, and the
  cache holds the in-flight promise so concurrent targets in the same batch
  can't both miss it and fire duplicate calls.
- From PRD: when the LLM step fails but detection succeeded, still get raw
  findings — retries once (after a fixed 1s delay), then degrades to `null`
  explanation/fix without failing the target or scan.

## Layers touched

- Service: `src/services/scanner.ts` — `@anthropic-ai/sdk` dependency
  (`claude-sonnet-5` model, not Opus); `enrichFindings` step using structured
  tool-use output; fingerprint-based dedup cache scoped to the scan, keyed to
  an in-flight `Promise<EnrichedFinding[]>` rather than only the resolved
  result; retry-once-after-1s-delay-then-degrade on failure; the LLM call
  shares the target's existing `timeoutMs`; one summary log line per scan
  completion (enriched vs. failed finding counts). The Anthropic call is a
  mockable seam (tests never call the real API).
- Bootstrap: `src/index.ts` — validate `ANTHROPIC_API_KEY` is set at startup,
  inline alongside the existing `PORT`/`DB_PATH` reads; exit/throw with a
  clear message if missing.
- Route / UI: `src/routes/scans.ts` — `explanation`/`suggested_fix` included
  by default in the `GET /scans/:id` JSON (no opt-in flag).
  `src/routes/dashboard.ts` — findings sub-table renders `explanation`/
  `suggested_fix` inline under each finding when present; omits those lines
  entirely (no placeholder text) when null, so old pre-feature scans and
  degraded findings render cleanly.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: test seeds a scan with fixture Finding rows, mocks the
      Anthropic call, and `curl localhost:PORT/scans/:id` shows
      `explanation`/`suggested_fix` populated — same text renders inline in
      the findings sub-table on the dashboard ([[001]]). A second identical
      finding-set in the same scan doesn't trigger a second LLM call, even
      when both are dispatched concurrently in the same batch (assert via
      mock call count). Starting the server without `ANTHROPIC_API_KEY` set
      fails immediately with a clear error, not a runtime surprise mid-scan.

## Out of scope

- Prompt-injection hardening against attacker-controlled scanned content —
  accepted risk per the PRD; raw findings are always shown regardless of LLM
  output.
- Fire-and-forget/async enrichment that flips a target to `succeeded` before
  enrichment finishes — stays synchronous within `#processTarget` for v1, to
  avoid a second async completion state in the polling/dashboard model.
- A "re-enrich" backfill action for pre-feature scans with null
  `explanation`/`suggested_fix` — those just render blank permanently unless
  the scan is re-run.
- [[007]] findings-by-severity summary and [[008]] configurable User-Agent —
  separate issues, untouched here.
