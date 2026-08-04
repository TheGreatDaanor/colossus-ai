---
id: 003
title: Surface missing-header and insecure-cookie findings
status: open
type: afk
blocked-by: [001]
---

## Slice

Once a scan completes, a target missing Content-Security-Policy,
X-Frame-Options, X-Content-Type-Options, or Strict-Transport-Security — or
with insecure `Set-Cookie` flags (Secure/HttpOnly/SameSite) — now shows up as
Finding rows (`category`, `severity`, `confidence: definitive`) in
`GET /scans/:id`.

Severity-per-header mapping isn't pinned by the PRD beyond the five-value
scale (Critical/High/Medium/Low/Info); pick a reasonable mapping (e.g.
missing HSTS/CSP skew higher, missing X-Content-Type-Options lower) and note
the rationale in code.

## User stories covered

- From PRD: see which security response headers are missing, so I know about
  clickjacking/MIME-sniffing/HSTS/cookie risks — missing CSP,
  X-Frame-Options, X-Content-Type-Options, HSTS, or insecure cookie flags
  each produce a Finding.

## Layers touched

- Schema: `src/db/schema.ts` — `findings` table already defined in [[001]];
  this issue is the first to populate it.
- Service: `src/services/scanner.ts` — `detectHeaderFindings(headers)` feeding
  into per-target findings persistence, wired into the pipeline from [[001]].

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: scan a target whose mocked fetch response is missing all
      four headers and has an insecure cookie → `curl localhost:PORT/scans/:id`
      shows 5 Finding rows with `category`, `severity`, and
      `confidence: "definitive"`.

## Out of scope

- TLS findings — [[004]].
- CVE findings — [[005]].
- `explanation`/`suggested_fix` text — findings show `null` for these until
  [[006]] lands.
