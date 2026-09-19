# CONTEXT

The domain language of Colossus. This is a glossary and nothing else — no
implementation detail, no plans, no decisions that belong in an ADR or a PRD.

## Passive check

A check that sends the target **no payload designed to trigger a
vulnerability**. It may issue requests beyond the operator-submitted URL
(`robots.txt` is fetched today for banner detection; probing for exposed
files such as `/.env` would also qualify) — what makes a check passive is
the absence of attack input, not the absence of requests.

Contrast **active check**, which sends crafted input (a canary payload) in
order to observe whether the target mishandles it.

## Passive mode / active mode

The scan-level setting an operator chooses at submission (`mode` on a
scan). Distinct from the *passive/active check* distinction above:

- **Passive mode** runs only passive checks.
- **Active mode** runs passive checks *and* active checks, and requires the
  operator's authorization attestation — the attestation exists because
  active checks send payloads.

Every passive-mode scan's behavior is a strict subset of what the same
target would receive in active mode. A check being non-intrusive is not
sufficient reason to call it active, and mode is not a proxy for
"thorough".

## Confidence

A finding's `confidence` describes **the certainty of the observation**,
not the certainty that the observation is exploitable.

- **`definitive`** — the observation is a fact about the response. "The
  `Strict-Transport-Security` header is absent." "This cookie has no
  `HttpOnly` attribute."
- **`possible`** — the observation is equally certain, but whether it
  constitutes a weakness depends on context the scanner cannot see. "The
  CSP contains `unsafe-inline`" is definitely true and may be entirely
  intentional.

Exploitability is not encoded in `confidence`. It is what `severity`
grades and what the finding's explanation discusses.

## Finding category

The stable, greppable identity of a defect — kebab-case, one category per
distinct defect. A present-but-weak header is a *different* category from
an absent one (`weak-csp` is not `missing-csp`).

Category is deliberately the discriminator rather than the explanation,
because explanations are LLM-generated and therefore not stable enough to
identify a finding by.

## Scan target

A single URL checked within a scan. Operators submit targets directly;
targets may also be discovered from another target's response, in which
case the discovered target is an ordinary scan target that runs the
identical pipeline.

## Apex

The domain an operator registered: one label below a public suffix
(`example.com`, `example.co.uk`). Called the apex because it is the top of
the DNS zone — the bare name where the zone's own records live. An apex has
no subdomain part, and a **program**'s scope is anchored to apexes.

## Subdomain

Any name under an apex, one or more labels to its left (`blog.example.com`,
`vpn.internal.example.com`).

Subdomain is **relative, not absolute**: `internal.example.com` is a
subdomain *of* `example.com` and simultaneously the parent *of*
`vpn.internal.example.com`. Scope rules depend on this — a host is excluded
when it sits anywhere under an excluded subtree, not only when it matches an
exclusion exactly.

## Host

One concrete DNS name, treated as a single addressable thing. Host is the
noun; **apex** and **subdomain** are descriptions of where that noun sits.
`example.com` is a host *and* the apex; `blog.example.com` is a host *and* a
subdomain.

## Enumerated host

A host observed to exist under a **program**, recorded with the source that
revealed it.

Distinct from a **scan target**: an enumerated host is a *name*, a scan
target is a *URL* that runs the check pipeline. A live, in-scope enumerated
host spawns a scan target. An out-of-scope or unscoped one is recorded and
never touched.

## Scope status

Which of a program's lists an enumerated host falls under. Exactly one
applies, decided before anything touches the host:

- **`out_of_scope`** — matches an out-of-scope entry, directly or by sitting
  under one. Evaluated first, and always wins: an exclusion an operator
  wrote is never overridden by a more specific inclusion.
- **`in_scope`** — sits under an in-scope apex, or matches an in-scope host
  exactly.
- **`unscoped`** — matches neither list. The host is real and authorized by
  nobody, so it is recorded for the operator to decide on and never scanned.

`unscoped` is the durable state of a host, not a workflow step; the queue an
operator works through is a view over it.

## Program

The persistent object an engagement accumulates against: the in-scope list,
the out-of-scope list, the enumerated hosts found under them, and the scans
run against it. Hosts accumulate across scans, so the inventory can be
diffed over time.

**Scope** stays reserved for the rule set *inside* a program — the two lists
— never for the program itself.

## Subdomain takeover

A defect in which a host's DNS still points at a third-party provider
resource that no longer exists, letting anyone who claims that resource
serve content from the operator's name.

Confirming one is a two-part observation: DNS shows the reference is
dangling, and the provider's response confirms the resource is unclaimed.
Colossus reports the defect and how to remediate it; it never claims the
resource itself.
