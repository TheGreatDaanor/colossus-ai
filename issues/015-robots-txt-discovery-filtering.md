---
id: 015
title: Filter discovered links against robots.txt Disallow rules
status: done
type: afk
blocked-by: [014]
---

## Slice

A same-origin link that would otherwise be discovered by [[014]] is
skipped when it matches a `Disallow` rule in the target's `robots.txt` —
visible as a fixture page's link into a disallowed path never appearing as
a discovered `scan_targets` row, while other same-origin links from the
same page still are.

## User stories covered

- From PRD: discovery respects `robots.txt`.

## Layers touched

- Service: `src/services/discovery.ts` — `discoverLinks` gains a second
  parameter, `robotsTxt: string | null`; any returned URL whose path
  matches a `Disallow` rule is excluded.
- Service: `src/services/scanner.ts` — passes the target's already-fetched
  `robots.txt` body (fetched today for the passive banner check) through
  to `discoverLinks`.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: a scan against a fixture target whose `robots.txt` disallows `/admin` and whose page links to both `/admin/settings` and `/contact` results in `/contact` appearing as a discovered target and `/admin/settings` not appearing at all.

## Out of scope

- `robots.txt` fetch-failure handling beyond what the existing passive-scan
  fetch already does — no new failure mode introduced here.
- `Allow` rules, crawl-delay, sitemap directives — only `Disallow` matching
  is implemented.
