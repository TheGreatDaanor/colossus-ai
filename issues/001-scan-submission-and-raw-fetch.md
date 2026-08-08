---
id: 001
title: Accept a scan, fetch targets, and show raw results on a dashboard
status: open
type: human
blocked-by: []
---

## Slice

An operator can `POST /scans` with a list of URLs, get an id back immediately
with `status: pending`, then open `GET /dashboard` in a browser, click into
the scan, and watch raw response data (status code, headers, response time,
redirect target) show up per URL as it completes — no security detection
yet, just the plumbing that every later issue builds on, but seen on a page
instead of chased down with curl.

This is the thick foundational slice: it adds the DB schema, the HTTP
framework, Drizzle/SQLite, and a minimal server-rendered dashboard as
dependencies/surfaces (none exist in the repo yet). Justified per the skill's
dev-infrastructure exception — splitting this setup into its own
zero-visibility ticket would violate the tracer-bullet rule, so it's bundled
with the first real slice instead.

**Type is `human`, not `afk`, because this issue introduces the project's
first visual surface.** The dashboard itself is a plain, unstyled data table
with no design judgment involved (see [[PRD-endpoint-vulnerability-scanner]],
Implementation decisions), but per the skill's classify rule, visual output
gets eyes on it at least once before the pattern is trusted. Once a human has
confirmed this base template renders sensibly, later issues that only add
*fields* to it ([[003]], [[004]], [[005]], [[006]], [[007]], [[008]]) stay
`afk` — they're mechanically testable by asserting the new values appear,
with no new visual judgment call.

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
- From PRD: watch a scan's status and results in a browser — `GET /dashboard`
  lists scans with status; `GET /dashboard/scans/:id` renders per-target raw
  data as an HTML table.
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
- Route / UI: `src/routes/dashboard.ts` — `GET /dashboard` (table of scans:
  id, name, status, created_at, linking to detail) and
  `GET /dashboard/scans/:id` (table of that scan's targets: url, status,
  status_code, response_time_ms, redirect_location, error — plus a nested
  findings sub-table per target that loops over `target.findings` generically
  by field name). No findings exist yet, so that sub-table renders empty for
  now; it's built here so [[003]]–[[008]] only need to make `ScannerService`
  return richer data — none of them touch `dashboard.ts` again. Server-rendered
  HTML via template literals, no client JS, no CSS framework, no new
  dependency — reads the same `ScannerService` as the JSON routes.
- Infra: add Hono, `drizzle-orm`, and `better-sqlite3` as dependencies; Drizzle
  config and migration generation (never hand-edit generated files under
  `src/db/migrations/`). Pending migrations auto-run on server startup. DB
  file path via `DB_PATH` env var (default `./data/scanner.db`, gitignored).
  Server port via `PORT` env var (hardcoded fallback default).

## Implementation decisions specific to this slice

- Fetch concurrency: hand-rolled batching (chunks of 10, `Promise.all` per
  chunk), cap is per-scan not global.
- URL dedup: exact string match, no normalization.
- Malformed/disallowed-scheme URLs still get a `scan_targets` row
  (`status: 'invalid'`) rather than being dropped silently.
- `scans.status: 'failed'` fires only when zero URLs are valid after
  per-URL validation; an empty `urls: []` array is instead rejected at
  submission with `400` (nothing was submitted to attempt). Any scan with
  at least one processed target — however bad — is `status: 'completed'`.
- Validation failures return `400` with `{ error: string }`.
- Default scan name (when omitted): human-readable local timestamp, e.g.
  `Scan 2026-08-08 14:32:00`.
- `response_headers` stored with lowercased keys.
- `created_at`/`completed_at` use Drizzle's integer unix-ms
  `mode: 'timestamp'`.
- Redirects (3xx) captured via `fetch(..., { redirect: 'manual' })`,
  classified as `status: 'ok'` with `redirect_location` set — no separate
  `'redirected'` status.
- `response_time_ms` is `null` on timeout.
- Scans run as an unawaited in-process async function (fire-and-forget,
  no queue); a process restart mid-scan leaves it stuck at `'running'`
  with no recovery in v1.
- Console log line per URL is plain text, not structured JSON.
- Dashboard has no auto-refresh — manual reload only.
- `ScannerService`'s fetch call is a constructor-injected parameter
  (default: global `fetch`); route tests use Hono's `app.request()`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `curl -X POST localhost:PORT/scans -H 'content-type: application/json' -d '{"urls":["https://example.com"]}'` returns `{id, status: "pending", ...}`; a follow-up `curl localhost:PORT/scans/1` shows `status_code`/`response_headers`/`response_time_ms` for that target once the scan completes.
- [ ] Visible at: open `http://localhost:PORT/dashboard` in a browser — the
      submitted scan appears in the list; clicking it shows a table with that
      target's status, status code, response time, and redirect target.
      **Human: eyeball this render once before merging** — confirm the table
      isn't garbled/misaligned and the values line up with the row they
      describe.

## Out of scope

- SSRF/private-IP guard — [[002]].
- All Finding generation: headers/cookies ([[003]]), TLS ([[004]]), CVE ([[005]]).
- LLM explanation/suggested-fix enrichment — [[006]].
- `findings_by_severity` summary — [[007]].
- Configurable User-Agent — [[008]].
- Dashboard styling/design polish, client-side JS, pagination, filtering —
  the dashboard is a plain data table, not a designed product surface (see
  PRD Implementation decisions); a designed report stays out of scope per
  the PRD.
