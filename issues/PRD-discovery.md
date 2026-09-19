# Recon & Discovery

## Problem

Colossus only ever checks the exact URL and query params the operator
submits. Real misconfigurations — an unauthenticated admin form, an
IDOR-able endpoint, an XSS-able search box — routinely live one or two
clicks away from the submitted URL, and the operator has to already know
about them to get them checked at all.

## Solution

A bounded, same-origin crawl runs per operator-submitted target, discovering
additional same-origin pages and forms and feeding them back into the exact
same passive and active-scanning pipeline as an explicitly-submitted URL —
so discovery compounds the existing checks instead of producing a separate
list the operator has to act on by hand.

## User stories

- As the operator, submitting one URL gets me findings across the pages
  linked from it, so I don't have to already know every URL worth checking.
  - Acceptance: same-origin links and forms found on a submitted target's
    page are added as new `scan_targets` and run through the same checks.
- As the operator, discovery never leaves the origin I submitted, so I'm
  not exposing subdomains or other hosts I may not control to the scan.
  - Acceptance: a link to a different hostname, port, or scheme than the
    submitted target (including subdomains) is never followed or added as
    a target.
- As the operator, discovery has a hard ceiling, so one target with
  thousands of internal links can't blow up scan time.
  - Acceptance: at most 25 discovered pages per operator-submitted root
    target, and no page more than 2 links deep from that root, regardless
    of how much of the cap remains.
- As the operator, discovery respects `robots.txt`, so the scanner behaves
  like a well-behaved crawler even under my own authorization.
  - Acceptance: a same-origin link matching a `Disallow` rule in the
    target's `robots.txt` is not followed or added as a target.
- As the operator, discovery runs whether or not I opted into active
  scanning, so a passive-mode scan still benefits from a fuller target
  list.
  - Acceptance: `mode: "passive"` scans discover and add same-origin
    targets exactly as `mode: "active"` scans do; only the exploitation
    step (canary injection/confirmation) is gated by `mode`/attestation,
    not discovery itself.
- As the operator, I can see how a discovered target was found, so I can
  reconstruct the site map from a scan's results.
  - Acceptance: a discovered `scan_targets` row has `discoveredFrom` set to
    the id of the target it was found on; an operator-submitted row has it
    `null`.

## Data model

Extends `scan_targets`:

| column | type | nullable |
|---|---|---|
| discovered_from | integer, FK → scan_targets.id | yes (null for operator-submitted targets) |

No other schema changes. Depth is computed by walking `discovered_from`
back to a null-parent row, rather than storing a separate depth counter.

## Modules

```
NEW      src/services/discovery.ts — pure module, no I/O of its own: parses
         a fetched page's HTML for same-origin <a href> links and <form>
         action URLs, filters out anything disallowed by the target's
         robots.txt, and returns the set of URLs eligible for discovery on
         that page.
         Public interface:
           discoverLinks(page: { url: URL; html: string },
             robotsTxt: string | null): string[]
             // same-origin, robots-allowed URLs found on this page

MODIFY   ScannerService (src/services/scanner.ts) — after a target's
         passive fetch completes, calls discovery.discoverLinks on the
         response body; for each returned URL not already a target on this
         scan, inserts a new scan_targets row with discoveredFrom set to
         the source target's id, and feeds it through the same
         passive/active pipeline as any other target — bounded by the
         25-page cap and depth-2 limit per root target.
```

`discovery.ts` stays a pure parsing/filtering module deliberately: it owns
no fetching, no persistence, and no scan orchestration, so it can be unit
tested without a database or network mock. `ScannerService` remains the
only place that decides what becomes a `scan_targets` row.

## Implementation decisions

- Scope: strict same-origin match — scheme, hostname, and port must all
  match the operator-submitted root target. Subdomains and other ports are
  never crawled; the operator attested authorization for the URLs they
  submitted, not for every subdomain a crawler might find.
- Bounds: depth-2, hard cap of 25 discovered pages per operator-submitted
  root target. The cap is not configurable in this phase.
- `robots.txt` is honored — a discovered link matching a `Disallow` rule is
  skipped, using the same `robots.txt` fetch the passive scanner already
  performs per target.
- Discovery runs independently of `mode`. It performs no payload
  injection, so it isn't gated by the active-mode attestation flag that
  exists specifically because active checks send real payloads to a
  target.
- Static HTML parsing only — no headless browser during discovery itself.
  A discovered target that later runs through active-mode XSS confirmation
  uses the existing Playwright-based `active-scanner.ts` from
  `PRD-active-scanning.md`, not discovery's own parsing.

## Testing decisions

- `discovery.ts`: pure unit tests against fixture HTML strings and
  `robots.txt` text — same-origin filtering, form-action extraction, and
  `Disallow` filtering are all testable without a database, network mock,
  or fetch of any kind.
- `ScannerService`'s discovery wiring: tested via the existing
  fetch-mock-based `ScannerService` test harness — asserting a discovered
  same-origin link becomes a new `scan_targets` row with `discoveredFrom`
  set, and that the 25-page/depth-2 caps are enforced by feeding a fixture
  page with more same-origin links than the cap allows.
- Deliberately untested: real network behavior of `robots.txt` fetch
  failures beyond what the existing passive-scan `robots.txt` fetch
  already covers — no new failure mode is introduced by discovery reusing
  it.

## Out of scope

- Subdomain enumeration — a distinct attack surface the operator may not
  control; rejected in the earlier grilling round specifically to avoid
  silently widening the authorization boundary the attestation gate
  establishes.
- Following cross-origin links at all — rejected for the same reason.
- Authenticated/logged-in crawling — no session/auth-state handling exists
  anywhere in Colossus yet; deferred to the future access-control/auth
  phase in `ROADMAP.md`.
- JS execution during crawl — discovery is static HTML parsing only; a
  headless browser is only used downstream by active-mode XSS confirmation
  (`PRD-active-scanning.md`), not by discovery itself.
- A configurable page cap or depth limit — the 25-page/depth-2 numbers are
  fixed for this phase; rejected as premature configurability with no
  operator having asked for it yet, mirroring how concurrency limits were
  treated in `PRD-active-scanning.md`.
