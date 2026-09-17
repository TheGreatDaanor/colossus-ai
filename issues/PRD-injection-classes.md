# Additional Injection Classes: SSTI, SQLi, LFI (Phase 3)

## Problem

Active scanning (`PRD-active-scanning.md`) confirms exactly one
vulnerability class — reflected XSS — by proving a canary `<script>`
marker *executes* in a headless browser. That mechanism is specific to
XSS: it can't confirm server-side injection classes that never touch the
DOM. An operator running Colossus against a target that is trivially
vulnerable to SSTI, SQL injection, or local file inclusion gets a clean
active-scan result today, because the tool has no confirmer for them.

## Solution

Extend active mode from one injection class to four by adding **SSTI**,
**error-based SQLi**, and **LFI** — all injected into query parameters,
all confirmed by a **deterministic response oracle** diffed against a
baseline (unmodified) fetch. These are fetch-based, not browser-based:
each does a baseline request and an injected request and confirms only on
a positive, deterministic differential.

This extends active scanning's "evidence-grounded, never a heuristic"
principle rather than weakening it. A finding is emitted only when the
oracle deterministically fires:

- **SSTI**: a unique arithmetic expression (two random factors) is
  injected; confirmed iff the computed *product* appears in the response
  and the literal expression does not — proof the template engine
  evaluated it.
- **SQLi (error-based)**: a syntax-breaking token (`'`) is injected;
  confirmed iff a known DB error signature (`SQL syntax`, `ORA-\d`,
  `PG::`, `SQLITE_ERROR`, …) appears that was **absent** from the baseline
  response.
- **LFI**: a traversal to a known-content file
  (`../../../../etc/passwd`) is injected; confirmed iff a stable signature
  (`root:.*:0:0:`) appears.

There is deliberately no timing oracle, no out-of-band callback, and no
"payload appears unescaped" heuristic. Classes that can only be confirmed
that way stay out of scope.

## User stories

- As the operator, when I run an active scan I get SSTI, SQLi, and LFI
  confirmed alongside XSS, so a clean result means clean across all four
  classes rather than XSS-only.
  - Acceptance: `mode: "active"` runs all four injection classes against
    every target's query parameters; the request surface is unchanged (no
    new body field).
- As the operator, each confirmed non-XSS finding shows me the response
  evidence that proved it, so I can trust it without re-running by hand.
  - Acceptance: a confirmed SSTI/SQLi/LFI finding is a `findings` row with
    the class's `category`, `severity: "high"`, `confidence:
    "definitive"`, the injection point and payload recorded, and the
    matched response snippet (plus a little surrounding context) stored in
    a new `evidence_snippet` column.
- As the operator, added classes don't exhaust my machine, so a scan with
  several targets stays usable.
  - Acceptance: the fetch-based classes (SSTI/SQLi/LFI) run under the
    passive fetch concurrency budget; only XSS uses the heavier Playwright
    browser cap.
- As the operator, the new classes can't become a hole in my SSRF
  protection.
  - Acceptance: every fetch a confirmer makes (baseline and injected)
    goes through the same `findDisallowedAddress` guard as passive
    fetches.

## Data model

Extends `findings`:

| column | type | nullable |
|---|---|---|
| evidence_snippet | text | yes (the matched response substring + context, for oracle-confirmed classes) |

`FindingCategory` gains values: `'ssti' | 'sqli' | 'lfi'` (was `'xss'`
plus the passive categories). No new table; `evidence_path` stays the
XSS-screenshot channel and is null for oracle-confirmed classes.

## Modules

```
NEW/REFACTORED  src/services/active-scanner.ts
      Extract an `InjectionClass` interface — the internal strategy shape
      for one injection class:
        interface InjectionClass {
          category: FindingCategory;         // 'xss' | 'ssti' | 'sqli' | 'lfi'
          enumerate(target: URL): InjectionPoint[];
          confirm(point: InjectionPoint): Promise<InjectionAttemptResult>;
        }
      XSS becomes the first implementation, its Playwright lifecycle moved
      behind `confirm` unchanged. SSTI/SQLi/LFI are fetch-based
      implementations reusing the passive fetch path + SSRF guard.

MODIFIED  ScannerService (src/services/scanner.ts)
      Runs every enabled InjectionClass over each active-mode target.
      Fetch-based classes run under the passive fetch concurrency budget;
      XSS keeps the browser cap.

MODIFIED  src/db/schema.ts (+ migration) — FindingCategory values and the
      evidence_snippet column.
```

## Implementation decisions

- Injection points: URL query parameters only, same as XSS — no forms, no
  crawling, no header/body injection.
- Confirmation is a deterministic differential against a baseline fetch.
  No timing oracle, no out-of-band callback, no unescaped-reflection
  heuristic.
- All confirmed findings are `severity: "high"`, `confidence:
  "definitive"`.
- The request surface is unchanged: `mode: "active"` runs all four
  classes. Per-class selection is deferred to a later refinement if
  operators ask for it.
- Fetch-based classes share the passive fetch concurrency budget; the
  Playwright browser cap remains XSS-specific because it exists for
  Chromium's weight.

## Out of scope

Deferred to future phases, each its own future PRD/slice:

- Blind / timing-based SQLi and command injection (probabilistic
  confirmation — no deterministic oracle for a black-box scanner).
- XXE (needs an error/file-read oracle or an out-of-band collector — new
  infra).
- Windows-path LFI variants and non-`/etc/passwd` LFI targets.
- IDOR, auth/OAuth/OIDC/SAML/JWT flaws, GraphQL attacks — not injection;
  they need a session/credential model this tool doesn't have.
- Form-based, header-based, or body-based injection points.
- Per-class selection in the request body.
- Web crawling / discovery beyond the operator-submitted URL list.
