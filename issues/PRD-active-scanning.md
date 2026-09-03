# Active Scanning, Browser Verification & Exploit Confirmation (Phase 2)

## Problem

Passive detection (headers, TLS, CVE-banner matching — the v1 scanner in
`PRD-endpoint-vulnerability-scanner.md`) tells the operator what *might* be
wrong. It can't tell them whether a suspected vulnerability is actually
exploitable. A missing CSP header is a real finding either way; a reflected
XSS "finding" based only on the absence of output-encoding heuristics is a
guess an operator still has to go verify by hand.

## Solution

An opt-in `mode: "active"` extension to the existing scan submission that,
for each target's URL query parameters, injects a harmless canary payload
and uses a real headless browser (Playwright) to confirm whether it
executes. A confirmed execution becomes a `findings` row with
`confidence: "definitive"`, distinct from the `"possible"` confidence
already used for CVE-banner matches. Detection stays evidence-grounded: a
finding is only emitted when the canary is proven to have run, never from a
heuristic guess.

This is intentionally the smallest possible slice that proves out three new
capabilities at once — active payload injection, browser-based execution
verification, and exploit confirmation — without expanding into the wider
vulnerability-class or crawling surface Orthrus covers. Each of those stays
a separate, later phase (see Out of scope).

## User stories

- As the operator, I can opt a scan into active mode, so that findings can
  be confirmed rather than guessed at.
  - Acceptance: `POST /scans` accepts `mode: "passive" | "active"`
    (default `"passive"`); passive-mode behavior is unchanged.
- As the operator, I must explicitly attest I'm authorized to actively test
  these targets, so the tool doesn't become an unattended attack tool.
  - Acceptance: `mode: "active"` requires `confirmAuthorized: true` in the
    request body or the scan is rejected before any target is touched; an
    optional `authorizationNote: string` is stored alongside it on the
    `scans` row for an audit trail.
- As the operator, I can see which of my target URLs have a confirmed,
  browser-verified reflected XSS, so I know it's real and not a guess.
  - Acceptance: for each query parameter on a target URL, a canary payload
    (a unique marker, e.g. `<script>window.__colossus_xss_marker='<uuid>'
    </script>`) is injected as that parameter's value; Playwright loads the
    resulting page and checks whether the marker executed. Execution
    produces a `findings` row: `category: "xss"`, `severity: "high"`,
    `confidence: "definitive"`, with the injection point and payload
    recorded.
- As the operator, I get a screenshot as evidence for every confirmed
  finding, so I have proof, not just a boolean.
  - Acceptance: on confirmation, Playwright captures a screenshot, saved to
    `data/evidence/`, path stored on the finding as `evidencePath`.
- As the operator, I can tell "not vulnerable" apart from "we couldn't
  test it", so I know whether to trust a clean result.
  - Acceptance: each active-scan attempt resolves to one of `confirmed`,
    `not_vulnerable` (payload sent, no execution, no errors), or
    `unavailable` (browser/infra failure — retried once, then recorded as
    such); only `confirmed` produces a finding, but all three states are
    visible on the scan target so a clean result is never confused with an
    untested one.
- As the operator, active scanning doesn't become a hole in my own SSRF
  protection, so a redirect chain during page load can't reach an internal
  address the pre-fetch guard already blocked.
  - Acceptance: every navigation and redirect inside the Playwright page is
    checked against the same disallowed-address guard used for passive
    fetches (`findDisallowedAddress`); a request to a disallowed address is
    aborted and the attempt is recorded as `unavailable` with an
    explanatory error, not silently followed.
- As the operator, active scanning doesn't exhaust my machine, so a scan
  with several targets stays usable.
  - Acceptance: active-mode targets run with a concurrency cap of 2-3
    concurrent Playwright browser contexts, independent of the passive
    scan's concurrency.

## Data model

Extends `findings` (no new table for v1):

| column | type | nullable |
|---|---|---|
| injection_point | text | yes (null for non-active findings) |
| payload | text | yes |
| evidence_path | text | yes |

Extends `scans`:

| column | type | nullable |
|---|---|---|
| mode | text (`passive`\|`active`) | no, defaults `passive` |
| confirm_authorized | boolean | yes (required true when mode=active) |
| authorization_note | text | yes |

## Modules

```
NEW   src/services/active-scanner.ts — new deep module: owns query-param
      injection-point selection, canary payload generation, Playwright
      browser lifecycle, in-browser SSRF/redirect guarding, execution
      confirmation, and evidence capture. Orchestrated by ScannerService,
      not called directly by routes — same relationship ScannerService
      already has with its own private CVE/LLM internals.
      Public interface (called from ScannerService):
        confirmXss(targetUrl: URL): Promise<XssAttemptResult>
          // XssAttemptResult = { outcome: "confirmed" | "not_vulnerable" | "unavailable",
          //                      injectionPoint?, payload?, evidencePath?, error? }

MODIFIED  ScannerService (src/services/scanner.ts)
      — startScan accepts mode/confirmAuthorized/authorizationNote;
        #runScan dispatches active-mode targets to active-scanner.ts at a
        separate, lower concurrency cap than passive targets.

MODIFIED  src/routes/scans.ts — validates mode/confirmAuthorized before
      calling ScannerService.startScan.
```

## Implementation decisions

- Injection points: URL query parameters only. No form discovery, no
  crawling, no header/cookie/body injection.
- Payloads: canary/marker-only. Never a payload that exfiltrates data,
  redirects to an external host, or persists (no stored/second-order XSS).
- Confirmation requires actual in-browser execution of the marker via
  Playwright — never a heuristic (e.g. "payload appears unescaped in
  response HTML") standing in for proof.
- Authorization gate is attestation-only (a boolean + optional free-text
  note), not verified against any external ownership proof — appropriate
  for the single-local-user threat model this tool already targets; revisit
  if the tool ever stops being single-user.
- In-browser navigation reuses the existing SSRF guard on every request the
  page makes, not just the initial URL.
- No job queue: active scans run in-process, same as passive, just at a
  smaller concurrency cap. Revisit only if a second active-scan module
  makes single-process concurrency a real bottleneck.

## Out of scope

Deferred to future phases, each its own future PRD/slice:

- Any vulnerability class other than reflected XSS: SQLi, command
  injection, SSTI, LFI/XXE, IDOR, auth/OAuth/OIDC/SAML/JWT flaws, GraphQL
  attacks, SSRF *exploitation* (only SSRF *defense* exists today).
- Form-based or body/header-based injection points.
- Stored/DOM/second-order XSS.
- Web crawling or any discovery beyond the operator-submitted URL list.
- A job queue / distributed scanning (BullMQ+Redis or similar).
- Richer evidence (video, HAR capture) beyond a single screenshot.
- Verified/proof-of-ownership authorization (e.g. DNS TXT record) — v1
  stays attestation-only.
