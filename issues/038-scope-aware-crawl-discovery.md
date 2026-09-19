---
id: 038
title: Follow crawled links to any in-scope host
status: open
type: afk
blocked-by: [032]
---

## Slice

Crawling `example.com` now follows a link to `blog.example.com` when the
program says it is in scope, and records hosts that CT never saw because they
never had a certificate.

## User stories covered

- From PRD: crawling follows links to any in-scope host, so that hosts with no
  certificate are still found.

## Layers touched

- Schema: none — reuses `enumerated_hosts.source` with value `crawl`.
- Service: `src/services/discovery.ts` — `isSameOrigin` is replaced by a
  program-scope check. A crawled host not already in the inventory is recorded
  via `recordHosts`. Depth and page caps continue to count from the root
  target and are **not** reset by a cross-host hop.
- Route / UI: the inventory distinguishes `crawl`-sourced hosts.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a scan of a stubbed page linking to an in-scope subdomain
      follows it and records the host with source `crawl`; a link to an
      out-of-scope host is not followed.

## Out of scope

- The existing depth-2 and 25-page caps are unchanged.
- `robots.txt` filtering is unchanged.
- Links to unscoped hosts are recorded, never followed.
