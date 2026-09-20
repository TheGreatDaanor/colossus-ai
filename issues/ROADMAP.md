# Roadmap: closing the gap toward Orthrus-style coverage

Context: Colossus started as a passive-only scanner (headers, TLS, cookie
flags, CVE-banner matching). `PRD-active-scanning.md` (phase 2, issues
`009`-`013`) adds the first active-scanning capability: browser-confirmed
reflected XSS via canary payloads injected into query params. This document
plans what comes after phase 2 ships.

This is a roadmap, not a set of PRDs. Phase 3 is planned in full detail
because its decisions are already settled; phases 4-6 are one-line
placeholders, written down so a phase doesn't get silently reinvented or
scope-crept into a neighboring one — not because they're ready to build.
Each phase gets its own PRD, written when it's actually about to start
(not now), the same way `PRD-active-scanning.md` was only written once
phase 2 was ready to be issue-cut.

## Phase 3 — Recon & discovery

**Why this is next:** every other future phase (more injection classes,
IDOR, more XSS injection points) is bottlenecked on the same limitation:
Colossus only ever looks at the exact URL and query params the operator
submitted. Discovery is infrastructure, not a vulnerability class — it's
the one phase that makes every later phase strictly more capable once
built, rather than being one more parallel checker bolted onto a still-narrow
surface.

**Problem:** an operator submitting `https://example.com` gets checked only
on that one page. Real misconfigurations (an unauthenticated admin form, an
IDOR-able endpoint, an XSS-able search box) routinely live one or two clicks
away, and the operator has to already know the URL to get it checked at
all.

**Solution:** a bounded crawl per operator-submitted target — same-origin as
phase 3 shipped it, since widened to any in-scope host by ADR 0001 —
that discovers additional pages and forms, feeding them back into the exact
same passive + active pipeline as an explicitly-submitted URL — so
discovery compounds the existing checks instead of producing a separate
list the operator has to act on by hand.

**Decisions (settled):**

- **Scope:** ~~same-origin only, strict match — scheme + exact hostname +
  port must match the submitted target. Subdomains (`blog.example.com`)
  and other ports are out of scope and never crawled; the operator attested
  authorization for the URLs they submitted, not for every subdomain a
  crawler happens to find.~~

  **Superseded by [ADR 0001](../docs/adr/0001-program-scoped-subdomain-enumeration.md).**
  Authorization is no longer inferred from the submitted URL: it is declared
  up front as a **program** with in-scope and out-of-scope lists, and
  subdomains under an in-scope apex are authorized by default. Crawling
  follows links to any in-scope host rather than stopping at an exact
  hostname match. The reversal is driven by subdomain takeover, a
  high-severity class that same-origin scanning structurally cannot see. See
  `PRD-subdomain-enumeration.md` and issues 029-040.

  Deny-by-default survived the reversal — a host matching neither list is
  recorded and never scanned. What changed is *how* the operator grants
  scope, not that they must.
- **Bounds:** depth-2, hard cap of 25 discovered pages per
  operator-submitted target, regardless of how much depth remains.
- **`robots.txt`:** honored. Crawling skips any path `Disallow`'d by the
  target's `robots.txt` (already fetched today for the passive banner
  check) — costs nothing and keeps the tool's behavior defensible even
  under operator attestation.
- **Discovered targets become real `scan_targets` rows:** run through the
  identical pipeline as a submitted URL (passive checks always; active XSS
  checks when `mode: "active"`). A `discovered_from` column (nullable, FK
  to another `scan_targets.id`) records provenance and lets depth be
  computed by walking the parent chain, rather than needing a separate
  depth counter.
- **Mode-independence:** discovery runs in *both* passive and active mode.
  It's non-intrusive (HTML parsing, no payloads), so gating it behind the
  active-mode attestation flag — which exists specifically because active
  checks send real payloads — would conflate two different risk
  categories. A passive-mode scan gets a richer target list too.
- **Module boundary:** new `src/services/discovery.ts`, parallel to
  `active-scanner.ts` from phase 2 — not folded into it, since discovery is
  orthogonal to (not a sub-feature of) exploit confirmation, and the
  mode-independence decision above only holds if the code reflects that
  split.

**Out of scope for phase 3:** ~~subdomain enumeration~~ (see ADR 0001 —
now a phase of its own), following links to hosts outside the program's
scope, authenticated/logged-in crawling, JS
execution during crawl (static HTML parsing only — no headless browser
needed for discovery itself, only for the XSS confirmation phase 2 already
does downstream of it).

## Future phases (placeholders — not yet planned in detail)

4. **More injection classes** (SQLi, command injection, SSTI, LFI/XXE) —
   reuses the canary/confirmation pipeline shape phase 2 establishes
   (error-based or time-based detection instead of browser execution), and
   benefits directly from phase 3's form/param discovery for injection
   points beyond query strings.
5. **Access control** (IDOR) — grilled and now committed via
   [ADR 0002](../docs/adr/0002-operator-supplied-ephemeral-identities.md) and
   `PRD-access-control-phase5.md`. The grilling split the original
   "access-control & auth" bucket in two: IDOR goes first, as a new
   **access-control check** family that confirms defects by replaying a request
   across operator-supplied, ephemeral identities (no login automation, no
   stored credentials). JWT/OAuth/SAML token & protocol inspection splits off
   into its own later phase, and vertical privilege escalation is deferred.
6. **SSRF exploitation + GraphQL** — Colossus only has SSRF *defense*
   today (the guard that stops the scanner itself from being tricked into
   hitting internal addresses); actually testing a *target* for SSRF
   requires out-of-band callback infrastructure, a genuinely new kind of
   dependency not needed by anything else on this roadmap.

## Explicitly not on this roadmap

Recon breadth beyond what's listed above — JS/source-map analysis, WAF
detection, API/GraphQL schema discovery — is Orthrus surface this roadmap
does not commit to matching. Each would need its own grilling session
before being added here.

Subdomain enumeration was on this list. It got its grilling session, and is
now committed to via [ADR 0001](../docs/adr/0001-program-scoped-subdomain-enumeration.md)
and `PRD-subdomain-enumeration.md`. DNS brute-force enumeration (as opposed
to Certificate Transparency), and additional CT sources beyond crt.sh,
remain deferred.
