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
