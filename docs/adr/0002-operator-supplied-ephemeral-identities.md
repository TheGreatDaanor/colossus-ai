---
status: accepted
---

# Operator-supplied, ephemeral identities for access-control testing

Phase 5 (IDOR / access control) confirms a defect by replaying one request as
two or more identities and comparing what each receives. This requires
Colossus to act as authenticated principals — the first capability on the
roadmap that needs authenticated state at all. We decided that an **identity
is opaque session material supplied by the operator per scan, never minted by
Colossus and never persisted**: the operator hands over a bundle of request
headers (a `Cookie` or `Authorization` set) plus a short list of URLs private
to that principal, and Colossus attaches the headers verbatim for the duration
of the scan and then drops them.

## Considered options

- **Colossus drives a login flow from operator-supplied credentials.**
  Rejected: login automation is an enormous, per-target-bespoke surface —
  CSRF tokens, MFA, CAPTCHA, redirect chains, session refresh — that is a
  product in its own right and wildly out of proportion to the phase. Making
  identities opaque sidesteps all of it.
- **Persist identities on the `program`, alongside enumerated hosts.**
  Rejected: session material is live credentials, and the program is durable,
  diffed-over-time state. Storing credentials at rest is a real liability, and
  the sessions are opaque and non-refreshable — they go stale fast. An
  identity is therefore the deliberate inverse of an enumerated host: durable
  host inventory versus ephemeral scan input.
- **Parameter-tampering confirmation (increment an object id) with a single
  identity.** Rejected: it has no deterministic baseline — a `200` on a
  guessed id could be the requester's own object, a public record, or a
  decoy. Confirming a *different owner* requires a second identity, so this is
  the same probabilistic confirmation the injection-class doctrine already
  bans. Cross-identity replay is the only strategy that yields a deterministic
  differential.

## Consequences

- Access-control checks run in **active mode only** and behind a **new
  identity-ownership attestation** layered on the existing active-mode
  attestation: the operator asserts they legitimately control the identities
  supplied. Replaying a real session is an authenticated action against the
  target.
- A stale or expired session mid-scan is a **reported error**, not something
  Colossus re-authenticates around — a direct consequence of identities being
  opaque and non-refreshable.
- Confirmed findings record a differential over **response digests and
  statuses, never the private body**, and suppress the evidence snippet other
  findings carry. The evidence of an IDOR *is* the victim's private data, so
  it must not be persisted or passed to LLM enrichment.
- The ground-truth private URLs are **operator-declared per identity**, not
  crawled. Crawling as each identity would make discovery identity-aware — a
  large expansion of the phase-3 crawler — and is explicitly deferred.
- **Vertical privilege escalation is out of scope**: it needs a declared role
  ordering on the program that nothing models today. Phase 5 covers only
  horizontal IDOR and unauthenticated access, whose confirmation needs no
  privilege hierarchy — only peer and empty identities.
