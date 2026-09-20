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

A program is **one engagement, not one domain** — it models an authorization
boundary, and authorization is granted over an estate rather than per DNS
name. Its in-scope list therefore holds however many apexes that engagement
covers, and its exclusions are written once for all of them. A program
covering a single domain is just an engagement with one entry; the reverse —
expressing "these domains share one authorization" — is not available if
programs are per-domain.

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

## Injection class

One kind of defect an **active check** confirms by sending a crafted payload
into an injection point and observing how the target mishandles it. Each
class is a self-contained strategy: it enumerates its injection points on a
target and confirms a hit on its own oracle. Reflected XSS, SSTI,
error-based SQLi, LFI, and CRLF injection are each an injection class.

Confirmation is always a **deterministic differential** against a baseline
(unmodified) response: a hit fires only on a positive, non-probabilistic
signal — an evaluated arithmetic product, a known error signature, a
known-file signature, an injected header reflected back. A class that can
only be confirmed by timing or an out-of-band callback is **not** an
injection class Colossus implements; the absence of a deterministic oracle
is what keeps such classes out, not the class of vulnerability itself.

Distinct from **finding category**: a category is the greppable identity a
confirmed hit is recorded under, whereas an injection class is the probe
that produces it. Most classes map to one category, but the mapping is not
part of the definition.

## Access-control check

One kind of defect confirmed not by sending a payload but by **replaying a
request as a different identity** and observing that the response does not
depend on who asked when it should. Sibling to an **injection class**, not a
member of it: both share the deterministic-differential doctrine — a hit
fires only on a hard, non-probabilistic signal — but the differential axis is
**identity, not payload**. An injection class varies the input to one
requester; an access-control check holds the request fixed and varies the
requester.

The confirmation is a **three-way differential** on one URL: the **owner**
identity establishes the ground-truth response, an **unauthorized** identity
(a peer, or the empty no-auth identity) replays it, and the result is a hit
only when the unauthorized identity receives the owner's ground-truth content
*and* a negative control proves the resource was genuinely access-controlled.
A resource that returns the same content to everyone is public, not a defect.

Confirmed access-control findings **suppress the evidence snippet** that other
findings carry, because the snippet would be the victim's private data — the
very content the defect exposes. The recorded proof is a differential over
response digests and statuses, never the private body itself.

## Identity

An **ephemeral scan input** representing one authenticated principal an
access-control check replays as: an opaque bundle of request headers (a
`Cookie` or `Authorization` set) the operator supplies and Colossus attaches
verbatim, paired with a short list of URLs known to be private to that
principal.

Colossus never parses, refreshes, or performs a login flow to mint an
identity — it is opaque session material, treated as a black box. An identity
is the deliberate **inverse of an enumerated host**: a host is durable
program state that accumulates and is diffed over time, whereas an identity is
live credential material, held only for the duration of one scan and never
persisted. The **empty identity** — no session at all — is a first-class
identity used both as the negative control for a horizontal finding and as
the probe for unauthenticated access.

## Ground-truth resource

The response an **owner** identity receives when it fetches its own private
URL — the baseline an access-control check tests against. It plays the role
the unmodified response plays for an injection class: the fixed point a hit is
a deviation from. An access-control hit is confirmed when an identity that
should not have the resource nonetheless receives a response matching the
ground-truth resource.
