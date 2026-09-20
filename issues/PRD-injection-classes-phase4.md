# More Injection Classes: CRLF Injection + LFI/SQLi Deepening (Phase 4)

## Problem

Active mode confirms four injection classes today — XSS, SSTI, error-based
SQLi, and LFI — all on a deterministic response oracle. Two gaps remain
inside that deterministic boundary: CRLF/response-header injection has no
confirmer at all, and the LFI and SQLi oracles are narrow (Unix
`/etc/passwd` only; a partial DBMS error-signature set), so a target
vulnerable on Windows or on an uncovered database engine reads clean.

## Solution

Add one new injection class — **CRLF injection**, confirmed when a header
injected through a query parameter is reflected back in the response
headers — and widen the two file/DB oracles: LFI gains a Windows
`win.ini` target, and SQLi gains the missing common DBMS error signatures.
Every addition keeps active mode's existing contract: a deterministic
differential against a baseline fetch, query-parameter injection points
only, and every fetch routed through the SSRF guard. No timing oracle, no
out-of-band callback, no unescaped-reflection heuristic.

## User stories

- As the operator, when I run an active scan I get CRLF injection confirmed
  alongside XSS, SSTI, SQLi, and LFI, so a clean result means clean across
  five classes rather than four.
  - Acceptance: `mode: "active"` runs the CRLF class against every target's
    query parameters; the request surface is unchanged (no new body field).
- As the operator, a confirmed CRLF finding shows me the injected header
  reflected in the response, so I can trust it without re-running by hand.
  - Acceptance: a confirmed CRLF finding is a `findings` row with category
    `crlf-injection`, `severity: "high"`, `confidence: "definitive"`, the
    injection point and payload recorded, and the reflected header line
    stored in `evidence_snippet`.
- As the operator, a CRLF finding fires only on real reflection, not on a
  header the server already sends, so I don't chase false positives.
  - Acceptance: confirmation requires the injected header to be present in
    the injected response's headers **and** absent from the baseline
    response's headers.
- As the operator, LFI catches Windows targets, not just Unix, so a
  vulnerable IIS/Windows host doesn't read clean.
  - Acceptance: the LFI class injects a Windows `win.ini` traversal in
    addition to `/etc/passwd`, and confirms on a Windows-file signature.
- As the operator, SQLi recognises the common database engines, so a
  vulnerable MySQL/MSSQL/DB2 backend doesn't read clean.
  - Acceptance: the SQLi error-signature set covers MySQL/MariaDB, MSSQL,
    and DB2 in addition to the engines already matched, each confirmed on a
    signature absent from the baseline response.
- As the operator, the new class can't become a hole in my SSRF
  protection.
  - Acceptance: every fetch the CRLF confirmer makes (baseline and
    injected) goes through the same `findDisallowedAddress` guard as the
    other fetch-based classes.
- As the operator, the added class doesn't exhaust my machine, so a scan
  with several targets stays usable.
  - Acceptance: the CRLF class runs under the passive fetch concurrency
    budget; only XSS uses the heavier Playwright browser cap.

## Data model

Extends `findings` — **no new column**. The reflected header line reuses
the existing `evidence_snippet` column (added in the Phase 3 injection-class
work) for oracle-confirmed classes; `evidence_path` stays the XSS-screenshot
channel and is null for CRLF findings.

`FindingCategory` gains one value:

| type | old | new |
|---|---|---|
| `FindingCategory` | `'xss' \| 'ssti' \| 'sqli' \| 'lfi'` (+ passive categories) | adds `'crlf-injection'` |

The LFI and SQLi deepening adds no category and no column — a Windows LFI
hit is still category `lfi`, an MSSQL hit still `sqli`.

## Modules

```
MODIFY  src/services/active-scanner.ts   (the deep module every class lives in)
  · Widen the shared fetch seam:
      BodyFetchImpl: (url) => Promise<string>
                  →  (url) => Promise<{ body: string; headers: Headers }>
    guardedFetchText and the SSTI/SQLi/LFI confirmers updated to read
    `.body` (they ignore `.headers`); one SSRF-guarded fetch chokepoint
    preserved.
  · NEW makeCrlfInjectionClass(fetchImpl?: BodyFetchImpl): InjectionClass
      category 'crlf-injection'; enumerate() mutates each query param with a
      CRLF header-injection payload; confirm() fires iff the injected header
      is present in the injected response's headers and absent from the
      baseline response's headers.
  · NEW crlfInjectionClass: InjectionClass — default instance backed by the
      SSRF-guarded fetch, mirroring sstiInjectionClass.
  · Deepen LFI: add a Windows win.ini traversal target and its signature
      alongside the existing /etc/passwd target.
  · Deepen SQLi: add MySQL/MariaDB, MSSQL, and DB2 error signatures to
      SQL_ERROR_SIGNATURES.

MODIFY  src/services/scanner.ts
  · Register crlfInjectionClass in #oracleClasses so it runs under the fetch
    semaphore (the passive fetch budget), alongside SSTI/SQLi/LFI. XSS keeps
    the browser cap. No other change — the loop already runs every
    InjectionClass over each active-mode target.

MODIFY  src/db/schema.ts (+ generated migration)
  · FindingCategory gains 'crlf-injection'. No new column.

DONE    CONTEXT.md — "injection class" glossary entry already added.
```

New public interface: `makeCrlfInjectionClass` / `crlfInjectionClass`
conform to the existing `InjectionClass` shape (`category` / `enumerate` /
`confirm`). The only interface change is widening `BodyFetchImpl` to return
`{ body, headers }`.

## Implementation decisions

- **Confirmation stays strictly deterministic.** A differential against a
  baseline (unmodified) fetch. No timing oracle, no out-of-band callback,
  no unescaped-reflection heuristic. This is why command injection, XXE,
  and blind SQLi are not in this phase (see Out of scope).
- **Injection points are query parameters only** — same surface as every
  existing class. No forms, no request body, no header injection points.
- **CRLF oracle:** the payload injects a uniquely-named header (a nonce, so
  it can't collide with a header the server already sends) via a
  `%0d%0a`-crafted parameter value; confirmed iff that header name appears
  in the injected response's headers and did **not** appear in the baseline
  response's headers. The stored `evidence_snippet` is the reflected header
  line.
- **CRLF severity/confidence:** `severity: "high"`, `confidence:
  "definitive"`, matching the Phase 3 convention for confirmed injection.
- **CRLF category slug:** `crlf-injection` — states exactly what is
  confirmed (a header was injected), not a consequence like
  `response-splitting` (a split body, which this oracle does not prove).
- **LFI deepening:** add the Windows `win.ini` traversal
  (`..\..\..\windows\win.ini` style) with a `[fonts]`/`[extensions]`
  signature, alongside the existing `/etc/passwd` (`root:.*:0:0:`) target.
  Both confirmed on a hard string signature and cleared against the
  baseline.
- **SQLi deepening:** add MySQL/MariaDB, MSSQL, and DB2 error signatures to
  the existing engine set; each match must be absent from the baseline
  response to confirm.
- **Fetch seam widened, not forked:** `BodyFetchImpl` returns `{ body,
  headers }` so the CRLF confirmer reads headers through the same
  SSRF-guarded fetch as the body-based classes. A second fetch path was
  rejected — one guarded chokepoint is the whole point of the SSRF design.
- **Request surface unchanged:** `mode: "active"` runs all classes; no
  per-class selection field. Existing confirmers read `.body` and ignore
  `.headers`.

## Testing decisions

- **CRLF class** — test `confirm` at the `BodyFetchImpl` seam (the pattern
  SSTI/SQLi/LFI already use): a fake fetch returning `{ body, headers }`
  drives each outcome. Cover: injected header reflected and absent from
  baseline → `confirmed`; injected header also present in baseline → not
  vulnerable (server sends it unconditionally); injected header absent from
  the injected response → not vulnerable; a fetch that throws →
  `unavailable`.
- **LFI/SQLi deepening** — one confirmation test per newly added signature
  (Windows `win.ini`; MySQL/MSSQL/DB2), plus a baseline-present case per
  oracle proving the differential still clears a signature the page shows
  unconditionally.
- **ScannerService** — one active-mode integration test asserting the CRLF
  class runs over an active target's query params and its finding
  round-trips through `getScan` with a non-null `evidence_snippet` and null
  `evidence_path`.
- **Widened fetch seam** — the existing SSTI/SQLi/LFI seam tests are updated
  to the `{ body, headers }` shape; this is the guard that the widening
  didn't silently break the body-based classes.
- **Deliberately untested:** the real network path of `guardedFetchText`
  (the SSRF guard has its own tests; confirmers are tested at the injected
  seam), and Chromium/XSS behaviour (unchanged by this phase).

## Out of scope

- **Command injection** — no deterministic response oracle over a black-box
  target that doesn't collide with SSTI's arithmetic oracle; the timing/OOB
  confirmation it really needs is barred by the deterministic-only
  decision.
- **XXE** — needs an error/file-read oracle or an out-of-band collector,
  and query parameters are not an XML input surface; near-zero deterministic
  hit rate here.
- **Blind / timing-based SQLi** — probabilistic; no deterministic oracle
  for a black-box scanner.
- **Out-of-band callback infrastructure** — the collector service that
  would unlock blind CmdI/XXE/SQLi deterministically is a genuinely new
  dependency, parked on the roadmap for a later phase, not pulled forward
  here.
- **Open redirect** — deterministic and query-param-native, but not
  injection: it stretches the `InjectionClass` abstraction (a redirect
  target, not a payload mishandled in a response). Deferred to its own
  framing.
- **`php://filter` and other PHP-wrapper LFI** — its "signature" is
  base64-that-decodes-to-source, which fails the deterministic
  string-signature bar this phase commits to.
- **Form-based, header-based, or request-body injection points** — surface
  stays query-params-only; widening the surface is a separate slice.
- **Per-class selection in the request body** — `mode: "active"` runs every
  class; deferred until operators ask for it.
- **Web crawling / discovery beyond the operator-submitted URL list** — a
  separate phase.

<!-- Lifecycle: delete this PRD once Phase 4 ships. A stale PRD in the repo
will mislead every future agent that finds it. -->
