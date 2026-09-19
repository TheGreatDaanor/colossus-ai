---
status: accepted
---

# Program-scoped subdomain enumeration

`ROADMAP.md` phase 3 settled that scanning is strictly same-origin — scheme,
exact hostname and port must match a submitted target — on the reasoning that
an operator attested authorization for the URLs they submitted, not for every
subdomain a crawler happens to find. We are reversing that: authorization is
now declared up front as a **program** with an in-scope and an out-of-scope
list, subdomains under an in-scope apex are authorized by default, and hosts
are enumerated from Certificate Transparency logs rather than only crawled.

The reversal is driven by **subdomain takeover**, a high-severity defect class
that same-origin scanning cannot see at all: it lives in the DNS records of
hosts the operator never thought to submit. Broader coverage of forgotten
staging and admin hosts is a real but secondary benefit.

## Considered options

- **Keep same-origin, enumerate nothing.** Rejected: leaves takeover
  permanently undetectable, and the coverage gap is exactly where neglected
  infrastructure lives.
- **Enumerate but never scan — emit a list the operator promotes by hand.**
  Rejected: the operator's authorization genuinely does extend across their
  estate, so making them re-submit each host is friction without a safety
  payoff.
- **Per-scan scope rather than a persistent program.** Rejected: an inventory
  that can be diffed over time is most of the value, and it requires hosts to
  accumulate against something that outlives a single scan.

## Consequences

- A **program** owns scans. This is a new entity above everything in the
  current data model, and it is the part of this decision that is expensive to
  undo.
- Authorization moves from per-URL to per-program, and becomes an axis
  independent of `mode`. Scope decides *which hosts*; mode decides *which
  checks*. Enumeration runs in passive mode, because reading CT logs sends the
  operator's infrastructure nothing.
- Exclusions are absolute: an out-of-scope entry is evaluated first and is
  never overridden by a more specific inclusion, so an operator can read an
  exclusion and know it held.
- A host matching neither list is `unscoped` — recorded, never scanned. Deny
  by default survives the reversal; what changed is how the operator grants
  scope, not that they must.
- `isSameOrigin` in `src/services/discovery.ts` becomes a program-scope check.
  Crawling may now follow links to any in-scope host, which also catches hosts
  that never received a certificate and are therefore invisible to CT.
- Colossus reports takeovers and how to remediate them; it never claims the
  dangling resource. Claiming creates a billable third-party resource under
  someone's credentials and cannot be undone by deleting a row — it is the
  operator's action, not the scanner's.
