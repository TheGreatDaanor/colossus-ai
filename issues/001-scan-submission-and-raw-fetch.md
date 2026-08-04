---
id: 001
title: Accept a scan, fetch targets, and return raw results
status: open
type: afk
blocked-by: []
---

## Slice

An operator can `POST /scans` with a list of URLs, get an id back immediately
with `status: pending`, then `GET /scans/:id` shortly after and see raw
response data (status code, headers, response time, redirect target) recorded
per URL — no security detection yet, just the plumbing that every later issue
builds on.

This is the thick foundational slice: it adds the DB schema, the HTTP
framework, and Drizzle/SQLite as dependencies (none exist in the repo yet).
Justified per the skill's dev-infrastructure exception — splitting this setup
into its own zero-visibility ticket would violate the tracer-bullet rule, so
it's bundled with the first real slice instead.

## User stories covered

- From PRD: submit up to 100 URLs; `POST /scans` with more is rejected.
- From PRD: use without login — no auth, plain auto-increment scan ids.
- From PRD: submit and check back later — `POST /scans` returns immediately
  with `status: pending`; `GET /scans/:id` reports current status/results.
- From PRD: list past scans — `GET /scans`, newest first.
- From PRD: name a scan — optional `name`, defaults to a timestamp-derived
  value if omitted.
- From PRD: export a scan's results as JSON — `GET /scans/:id` returns the
  full nested Scan → ScanTarget → Finding structure.
- From PRD: raw response data as an audit trail regardless of findings —
  ScanTarget stores status code, headers, TLS info (columns only for now),
  and response time unconditionally.
- From PRD: tell a slow scan from a broken one — `status`/`error` fields on
  Scan and ScanTarget, plus one console log line per URL as it's processed.
- From PRD: one bad URL doesn't ruin the whole scan — unreachable/timed-out
  targets are marked individually; the rest of the scan completes.
- From PRD: malformed URLs are skipped and flagged individually; duplicates
  within one submitted list are deduped silently.
- From PRD: only `http`/`https` schemes are accepted (scheme allowlist only —
  the private/loopback/metadata IP SSRF guard is [[002]], not here).

## Layers touched

- Schema: `src/db/schema.ts` — full PRD data model in one pass: `scans`,
  `scan_targets`, `findings` tables (findings stay unpopulated until 003+,
  but defining the shape now keeps every later issue additive-only).
- Service: `src/services/scanner.ts` — `ScannerService.startScan(urls, options?)`,
  `getScan(id)`, `listScans()`. Internals: URL-list validation (≤100, valid
  syntax, `http`/`https` scheme only, dedup), concurrency-10 fetch of `GET /`
  per target with a 10s per-target timeout and a 5MB response-body cap,
  per-target status machine (`pending`/`ok`/`unreachable`/`timeout`/`invalid`),
  scan-level status transitions (`pending`→`running`→`completed`/`failed`),
  one console log line per URL as it's processed. The fetch call itself is an
  injectable/mockable seam per the PRD's testing decisions.
- Route: `src/routes/scans.ts` — `POST /scans`, `GET /scans`, `GET /scans/:id`,
  thin, delegating entirely to `ScannerService`.
- Infra: add an HTTP framework, `drizzle-orm`, and a SQLite driver as
  dependencies; Drizzle config and migration generation (never hand-edit
  generated files under `src/db/migrations/`).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `curl -X POST localhost:PORT/scans -H 'content-type: application/json' -d '{"urls":["https://example.com"]}'` returns `{id, status: "pending", ...}`; a follow-up `curl localhost:PORT/scans/1` shows `status_code`/`response_headers`/`response_time_ms` for that target once the scan completes.

## Out of scope

- SSRF/private-IP guard — [[002]].
- All Finding generation: headers/cookies ([[003]]), TLS ([[004]]), CVE ([[005]]).
- LLM explanation/suggested-fix enrichment — [[006]].
- `findings_by_severity` summary — [[007]].
- Configurable User-Agent — [[008]].
