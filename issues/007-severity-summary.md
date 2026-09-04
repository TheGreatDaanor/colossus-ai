---
id: 007
title: Add findings-by-severity summary to scan results
status: done
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
- Route: `src/routes/scans.ts` — map the service's camelCase
  `findingsBySeverity` to the `findings_by_severity` wire key.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: test drives real findings of mixed severities through the
      scanner against a stubbed fetch (rather than seeding fixture rows);
      `curl localhost:PORT/scans/:id` response includes a
      `findings_by_severity` block with correct counts per level. (This
      summary block isn't rendered on the dashboard — [[001]]'s template only
      covers per-target/per-finding detail; adding it there is optional
      follow-up polish, not required for this issue's DoD.)

## Out of scope

- Changing how individual findings are generated — this issue only
  aggregates what [[003]]/[[004]]/[[005]] produce.
