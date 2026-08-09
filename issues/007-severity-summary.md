---
id: 007
title: Add findings-by-severity summary to scan results
status: open
type: afk
blocked-by: [001]
---

## Slice

`GET /scans/:id` now includes a `findings_by_severity` count block
(critical/high/medium/low/info counts) alongside the existing per-target,
per-finding detail.

## User stories covered

- From PRD: see a summary of findings by severity, so I get the gist without
  reading every finding — the JSON response includes a
  `findings_by_severity` count block.

## Layers touched

- Service: `src/services/scanner.ts` — aggregate existing findings by
  `severity` when serializing `getScan`'s result.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: test seeds fixture findings of mixed severities on a scan;
      `curl localhost:PORT/scans/:id` response includes a
      `findings_by_severity` block with correct counts per level. (This
      summary block isn't rendered on the dashboard — [[001]]'s template only
      covers per-target/per-finding detail; adding it there is optional
      follow-up polish, not required for this issue's DoD.)

## Out of scope

- Changing how individual findings are generated — this issue only
  aggregates what [[003]]/[[004]]/[[005]] produce.
