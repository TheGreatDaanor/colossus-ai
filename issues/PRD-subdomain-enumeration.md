# Subdomain Enumeration

## Problem

Colossus only ever checks hosts the operator explicitly submitted, and phase 3
discovery deliberately stops at the exact hostname it started from. Operators
routinely do not know their own estate — a forgotten `staging.` box or an
admin panel on a subdomain never gets checked because nobody remembered to
type it. Worse, a whole class of high-severity defect lives in DNS records
rather than HTTP responses, and is therefore invisible to every check
Colossus has: a subdomain whose DNS still points at a deprovisioned
third-party resource can be claimed by anyone, who then serves content from
the operator's own name.

## Solution

Authorization moves from per-URL to a **program**: a persistent object holding
an in-scope list, an out-of-scope list, and an accumulating inventory of
hosts. Hosts are enumerated from Certificate Transparency logs and from
crawling, classified against the program's scope lists before anything touches
them, and live in-scope hosts spawn ordinary scan targets that run the
existing pipeline. Because the inventory outlives any one scan, it can be
diffed over time — and because enumeration works at the DNS level, dangling
provider references can be detected and reported.

## User stories

- As an operator, I can create a program with in-scope and out-of-scope lists,
  so that authorization is declared once rather than per URL.
  - Acceptance: a program persists both lists and is referenced by subsequent
    scans.
- As an operator, creating a program from a submitted URL seeds its apex into
  the in-scope list, so that the common case takes one step.
  - Acceptance: creating a program from `https://example.com/x` proposes
    `example.com` as an in-scope entry.
- As an operator, I must confirm an inferred apex before enumeration runs, so
  that scope is never widened by a parser without my agreement.
  - Acceptance: enumeration does not run against an unconfirmed scope entry.
- As an operator, subdomains of an in-scope apex are in scope by default, so
  that I do not have to list every host I own.
  - Acceptance: with `example.com` in scope, `blog.example.com` classifies as
    `in_scope`.
- As an operator, I can put an exact host in scope without its apex, so that I
  can authorize one partner host in a domain I do not otherwise own.
  - Acceptance: with only `blog.partner.com` in scope, `www.partner.com`
    classifies as `unscoped`.
- As an operator, an out-of-scope entry always wins, so that an exclusion I
  wrote is one I can rely on.
  - Acceptance: with `example.com` in scope and `*.internal.example.com` out,
    `vpn.internal.example.com` classifies as `out_of_scope`.
- As an operator, hosts matching neither list are recorded but never scanned,
  so that I learn they exist without anything unauthorized being touched.
  - Acceptance: a host under a registrable domain absent from both lists
    classifies as `unscoped` and spawns no scan target.
- As an operator, hosts are enumerated from Certificate Transparency logs, so
  that my inventory includes hosts I never submitted.
  - Acceptance: hosts present in CT for an in-scope apex appear as enumerated
    hosts with source `ct-log`.
- As an operator, a CT source outage does not fail my scan, so that scanning
  degrades to stale inventory rather than stopping.
  - Acceptance: an enumeration failure is recorded on the program and the scan
    proceeds against the existing inventory.
- As an operator, wildcard DNS does not fill my inventory with fictitious
  hosts, so that the inventory stays trustworthy.
  - Acceptance: an apex whose random-nonce label resolves is flagged as
    wildcard, and unresolved inferred hosts under it are suppressed.
- As an operator, each live in-scope host is probed for scheme, so that
  HTTP-only legacy hosts are still checked.
  - Acceptance: a host answering only on `http://` spawns an `http://` scan
    target; a host answering on both spawns `https://`.
- As an operator, enumeration runs on a schedule as well as on demand, so that
  new hosts are noticed between scans.
  - Acceptance: a program enumerates on its schedule with no scan running, and
    on demand when a scan starts.
- As an operator, I can see which hosts appeared since last time, so that
  shadow IT surfaces.
  - Acceptance: the program's inventory distinguishes hosts by first-seen
    time; a newly appeared host is not emitted as a finding.
- As an operator, scanning is capped per scan while recording is not, so that
  a large estate neither truncates my inventory nor blows up scan time.
  - Acceptance: all enumerated hosts are recorded; at most 50 are scanned per
    scan.
- As an operator, newly appeared hosts are scanned first, so that the freshest
  surface is checked soonest.
  - Acceptance: selection takes hosts unscanned since first seen, then the
    least-recently-scanned, up to the cap.
- As an operator, a host that stops resolving is retained, so that a host
  disappearing and reappearing remains visible.
  - Acceptance: an NXDOMAIN host keeps its row and its history; it is excluded
    from scanning after 3 consecutive failed resolutions.
- As an operator, a dangling provider reference is reported as a takeover, so
  that I can reclaim it before someone else does.
  - Acceptance: a host whose CNAME target does not resolve, and whose provider
    response matches a known unclaimed fingerprint, produces a takeover
    finding at `definitive` confidence.
- As an operator, a takeover is reported on DNS evidence alone at lower
  confidence, so that a provider I have no fingerprint for is still surfaced.
  - Acceptance: a dangling CNAME with no fingerprint match produces a takeover
    finding at `possible` confidence.
- As an operator, Colossus never claims the dangling resource, so that no
  billable third-party resource is created on my behalf.
  - Acceptance: a takeover finding carries remediation text naming the
    provider and resource; no provider API is called.
- As an operator, crawling follows links to any in-scope host, so that hosts
  with no certificate are still found.
  - Acceptance: a link from `example.com` to `blog.example.com` is followed
    when in scope, and records an enumerated host with source `crawl`.

## Data model

New `programs`:

| column | type | nullable |
|---|---|---|
| id | integer, pk | no |
| name | text | no |
| enumeration_error | text | yes |
| last_enumerated_at | integer, timestamp | yes |
| created_at | integer, timestamp | no |

New `scope_entries`:

| column | type | nullable |
|---|---|---|
| id | integer, pk | no |
| program_id | integer, FK → programs.id | no |
| list | text, `in` \| `out` | no |
| pattern | text (apex, exact host, or `*.`-prefixed subtree) | no |
| confirmed_at | integer, timestamp (null until operator confirms an inferred entry) | yes |

New `enumerated_hosts`:

| column | type | nullable |
|---|---|---|
| id | integer, pk | no |
| program_id | integer, FK → programs.id | no |
| hostname | text (unique per program) | no |
| source | text, `ct-log` \| `crawl` | no |
| scope_status | text, `in_scope` \| `out_of_scope` \| `unscoped` | no |
| endpoint_url | text (scheme-probed URL, null when dead) | yes |
| is_wildcard | integer, boolean | no |
| failed_resolutions | integer, default 0 | no |
| first_seen_at | integer, timestamp | no |
| last_resolved_at | integer, timestamp | yes |
| last_scanned_at | integer, timestamp | yes |

New `takeover_findings` — separate from `findings` because its subject is a
DNS name, not a scan target, and the host frequently does not resolve:

| column | type | nullable |
|---|---|---|
| id | integer, pk | no |
| enumerated_host_id | integer, FK → enumerated_hosts.id | no |
| provider | text (null when no fingerprint matched) | yes |
| cname_target | text | no |
| severity | text, FindingSeverity | no |
| confidence | text, FindingConfidence | no |
| explanation | text | yes |
| suggested_fix | text | yes |
| detected_at | integer, timestamp | no |

Changed `scans`:

| column | type | nullable |
|---|---|---|
| program_id | integer, FK → programs.id | yes (null for legacy URL-only scans) |

Changed `scan_targets`:

| column | type | nullable |
|---|---|---|
| enumerated_host_id | integer, FK → enumerated_hosts.id | yes (null for operator-submitted targets) |

## Modules

```
NEW      src/services/programs.ts — the deep module. Owns apex computation
         (via the Public Suffix List), the ordered three-way scope
         classification, the host inventory, and scan selection. No other
         module knows what "in scope" means. Pure classification, no network.
         Public interface:
           classifyHost(hostname: string, scope: Scope): ScopeStatus
           recordHosts(programId: number, hosts: ObservedHost[]): Promise<EnumeratedHost[]>
           selectHostsToScan(programId: number, limit: number): Promise<EnumeratedHost[]>

NEW      src/services/enumeration.ts — all outbound I/O for finding hosts:
         the CT-log query, the wildcard nonce probe, and the scheme probe.
         Separate from programs.ts so scope rules stay testable without a
         network.
         Public interface:
           enumerate(apex: string): Promise<ObservedHost[]>
           resolveEndpoint(hostname: string): Promise<Endpoint | null>

NEW      src/services/takeover.ts — resolves a host's CNAME chain, matches the
         provider fingerprint table, and returns takeover evidence or nothing.
         Parallels passive-checks.ts, but its input is a DNS name rather than
         an HTTP response.
         Public interface:
           checkTakeover(hostname: string): Promise<TakeoverEvidence | null>

MODIFY   src/services/discovery.ts — isSameOrigin is replaced by a
         program-scope check: links to any in-scope host are followed, and a
         crawled host not already in the inventory is recorded with source
         `crawl`. Depth and page caps continue to count from the root target
         and are not reset by a cross-host hop.

MODIFY   src/services/scanner.ts — a scan resolves its targets from its
         program's inventory via selectHostsToScan, in addition to
         operator-submitted URLs, and runs takeover checks over in-scope hosts
         regardless of mode.

MODIFY   src/routes/scans.ts — program creation (seeding an apex from a
         submitted URL), scope-list editing, and confirmation of inferred
         entries.

MODIFY   src/db/schema.ts — the tables above.
```

## Implementation decisions

- **Apex** is the registrable domain, computed with the Public Suffix List —
  the one new runtime dependency accepted, because hand-rolling it is
  known-bad.
- **Scope entry grammar** is apex or exact host for the in-scope list, plus
  `*.`-prefixed subtrees for the out-of-scope list. Path prefixes and CIDR
  ranges are deferred.
- **Classification is one ordered rule, first match wins**: out-of-scope match
  → `out_of_scope`; else under an in-scope apex or matching an in-scope host
  → `in_scope`; else `unscoped`. An exclusion is never overridden by a more
  specific inclusion.
- **Unscoped hosts are recorded, never scanned.** Deny by default is retained.
- **Scope and mode are independent axes.** Scope decides which hosts, mode
  decides which checks. Enumeration and takeover checks run in passive mode,
  because reading CT logs and DNS sends the operator's infrastructure nothing.
- **Enumeration source is crt.sh only.** Censys and Google's CT API are a
  later phase.
- **Enumeration failure is non-fatal**: recorded on the program, scan proceeds
  against existing inventory. Results are cached so an on-demand enumeration
  immediately after a scheduled one does not re-query.
- **Enumeration cadence** is scheduled per program plus on demand at scan
  start.
- **Wildcard detection** resolves a random nonce label under the apex; if it
  resolves, the apex is flagged wildcard and unresolved inferred hosts under
  it are suppressed. A wildcard CT entry is recorded as a host with
  `is_wildcard` set and is never scanned.
- **Scheme probe**: try both, keep whichever responds, prefer HTTPS when both
  do. A host answering on neither has `endpoint_url` null and spawns no
  target.
- **Recording is uncapped; scanning is capped at 50 hosts per scan.**
  Truncating the inventory would make it look complete when it is not.
- **Selection order**: hosts never scanned since first seen, then
  least-recently-scanned, up to the cap.
- **Non-resolving hosts are retained forever** with `last_resolved_at`;
  excluded from scanning after 3 consecutive failed resolutions, but still
  eligible for takeover checks, because NXDOMAIN on a still-CNAME'd host is
  the takeover signal itself.
- **Takeover confidence**: dangling CNAME plus provider fingerprint match →
  `definitive`; dangling CNAME alone → `possible`. This matches the existing
  rule that confidence describes certainty of the observation.
- **Fingerprint table is hand-maintained** in-repo, covering S3, GitHub Pages,
  Heroku, Azure, Fastly and Shopify to start, grown on demand. Never fetched
  at runtime: a third party must not be able to change what Colossus asserts
  as `definitive`.
- **Colossus never claims a dangling resource.** It emits the provider,
  resource name and remediation; the operator acts.
- **Inferred scope entries require confirmation** before first enumeration,
  because inferring an apex from a URL is what widens authorization from one
  host to a whole domain.

## Testing decisions

- `programs.classifyHost` is the primary seam and is tested exhaustively as a
  pure function: apex/subtree matches, exact-host matches, exclusion
  precedence, unscoped fallthrough, public-suffix edge cases
  (`example.co.uk`), and case/trailing-dot normalisation. No database.
- `programs.selectHostsToScan` is tested against a seeded database for
  ordering and cap behaviour.
- `enumeration` is tested with a stubbed HTTP client and stubbed resolver:
  CT response parsing, wildcard nonce detection, scheme-probe preference, and
  the non-fatal failure path. The real crt.sh endpoint is never contacted in
  tests.
- `takeover.checkTakeover` is tested with a stubbed resolver and HTTP client
  across each fingerprinted provider, the dangling-without-fingerprint case,
  and the healthy-CNAME case.
- `discovery` keeps its existing tests, with the same-origin cases rewritten
  as scope cases, plus cross-host-in-scope and cross-host-out-of-scope.
- Deliberately untested: the Public Suffix List data itself (a vendored
  dataset, not our logic); the scheduler's timing (cadence is configuration,
  the enumeration it triggers is tested directly); and live CT/DNS
  behaviour — every network boundary is stubbed, so no test depends on a
  third party being up or on a real domain's records.

## Out of scope

- **DNS brute-force enumeration against a wordlist** — deferred; CT logs carry
  the yield without a wordlist to own, resolver rate limits, or abuse risk.
- **Censys and Google CT as additional sources** — a later phase; one source
  proven before taking two dependencies.
- **Claiming a dangling resource** — creates a billable third-party resource
  under someone's credentials and cannot be undone by deleting a row.
- **Automatic claiming, and storing operator provider credentials** — follows
  from the above.
- **Full bug-bounty scope grammar (URL path prefixes, IP/CIDR ranges)** — each
  drags in its own matching rules and an IP-versus-hostname resolution
  question; deferred until the domain/host grammar is proven.
- **Most-specific-entry-wins precedence** — more expressive, but an operator
  could no longer read an exclusion and know it held.
- **Emitting a newly appeared host as a finding** — a finding category is the
  identity of a *defect*, and a new host is not one. It is an inventory diff.
- **Enumerating hosts under a registrable domain absent from both lists** —
  recorded as `unscoped` only; nobody authorized them.
- **Per-operator persistent exclusion lists** — needs an operator identity
  model that does not exist yet; exclusions are per-program.
- **Retroactively scoping existing URL-only scans into programs** — `scans`
  keeps a nullable `program_id`; legacy scans stay as they are.
