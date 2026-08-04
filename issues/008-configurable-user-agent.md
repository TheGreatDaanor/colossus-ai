---
id: 008
title: Support configurable scanner User-Agent
status: open
type: afk
blocked-by: [001]
---

## Slice

The scanner sends a custom, self-identifying User-Agent on every outgoing
fetch. The default comes from a global env var/config value; a scan
submission may override it for that scan only.

## User stories covered

- From PRD: customize the User-Agent the scanner sends, so targets can
  identify what's hitting them or I can tailor it per engagement — a global
  default is set via config/env var; a scan request may override it for that
  scan only.

## Layers touched

- Service: `src/services/scanner.ts` — read the default User-Agent from
  env/config; accept an optional `userAgent` in `startScan` options; use it
  in the fetch pipeline from [[001]] for every request in that scan.
- Route: `src/routes/scans.ts` — `POST /scans` accepts an optional
  `userAgent` field, persisted to `scans.user_agent`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `curl -X POST localhost:PORT/scans -d '{"urls":["https://example.com"],"userAgent":"my-scanner/1.0"}'` — test asserts the mocked fetch for that scan is called with that header; a scan submitted without `userAgent` uses the configured global default.

## Out of scope

- Per-target User-Agent overrides — the PRD scopes overrides to the whole
  scan, not individual URLs within it.
