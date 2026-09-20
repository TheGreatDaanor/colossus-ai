# Access control (IDOR) — Phase 5

## Problem

Colossus checks every target as an anonymous requester and never as a logged-in
one, so it is structurally blind to the largest bucket of real bugs: broken
object-level authorization. An operator whose app leaks `/invoice/1234` to any
authenticated user — or to no one at all — gets a clean report, because nothing
in the tool ever asks "does this response depend on *who* asked?"

## Solution

A new **access-control check** family that confirms a defect by replaying one
request as several operator-supplied identities and comparing what each
receives. Each identity is an opaque bundle of request headers plus a short list
of URLs private to it. For every such URL, Colossus performs a three-way
differential — the owning identity establishes the ground-truth response, an
unauthorized peer replays it, and the empty (no-auth) identity acts as a
negative control — and reports a hit only on a deterministic match. Identities
are supplied per scan and never persisted; the checks run in active mode behind
a new identity-ownership attestation.

## User stories

- As an operator, I can attach one or more identities to an active-mode scan, so
  that Colossus can test access control as those principals.
  - Acceptance: a scan started with an `identities` list runs access-control
    checks; one started without any runs none.
- As an operator, I can supply each identity as an opaque header bundle (a
  `Cookie` or `Authorization` set), so that I never have to give Colossus my
  credentials or a login flow.
  - Acceptance: the exact headers I supply are attached verbatim to that
    identity's requests; Colossus neither parses nor modifies them.
- As an operator, I declare per identity the URLs known to be private to it, so
  that Colossus knows what to treat as ground-truth resources.
  - Acceptance: only URLs I declared for an identity are used as that identity's
    ground truth; no crawling occurs to find them.
- As an operator, I must attest that I control the supplied identities before an
  access-control scan runs, so that replaying real sessions is authorized.
  - Acceptance: an active-mode scan carrying identities is rejected unless the
    identity-ownership attestation is set, independently of the existing
    active-mode attestation.
- As an operator, I get an `idor` finding when a peer identity receives another
  identity's private resource, so that I can fix the missing object-level check.
  - Acceptance: a finding of category `idor` is recorded when the peer's
    response matches the owner's ground truth and the no-auth control diverges.
- As an operator, I get an `unauthenticated-resource-access` finding when a
  private resource is reachable with no session at all, so that I can require
  authentication.
  - Acceptance: a finding of category `unauthenticated-resource-access` is
    recorded when the no-auth control matches the owner's ground truth on a URL
    an identity treated as private.
- As an operator, I do not get a finding when a resource returns the same
  content to everyone, so that public pages are not reported as leaks.
  - Acceptance: when the no-auth control matches the owner ground truth and no
    identity distinguishes the resource, no finding is recorded.
- As an operator, a confirmed access-control finding never contains the victim's
  private data, so that the report itself does not leak what the defect exposes.
  - Acceptance: `idor` and `unauthenticated-resource-access` findings carry a
    digest/status differential and identity labels; `evidence_snippet` and
    `evidence_path` are null.
- As an operator, when an identity's session is stale mid-scan I get a reported
  error rather than a silent miss, so that I know to re-supply it.
  - Acceptance: a ground-truth fetch that fails authentication surfaces an error
    on the scan; Colossus does not attempt to re-authenticate.
- As an operator, my supplied identities are discarded when the scan completes,
  so that live credentials are never stored at rest.
  - Acceptance: no identity headers are persisted to the database at any point.

## Data model

No new tables. Identities are ephemeral scan inputs and are never persisted.

`findings` (modify) — one new nullable column, set only on access-control
findings (`idor`, `unauthenticated-resource-access`):

- `access_control_evidence` `text` nullable — compact JSON differential proof:
  the URL, the owner/peer/no-auth response statuses and normalized-body digests,
  and the owner and unauthorized identity labels. Contains **no** response body.

Existing `evidence_snippet` and `evidence_path` stay null for these categories.
`category` carries `idor` or `unauthenticated-resource-access`.

## Modules

```
NEW     src/services/access-control.ts   — the access-control check family
MODIFY  src/services/scanner.ts          — active-mode wiring, identities input, attestation
MODIFY  src/db/schema.ts                 — findings.access_control_evidence
```

**`src/services/access-control.ts`** — deep module, one entry point over all the
replay and oracle logic:

```ts
export interface Identity { label: string; headers: Record<string,string>; privateUrls: string[] }
export type AccessControlOutcome = {
  category: 'idor' | 'unauthenticated-resource-access';
  url: string;
  proof: AccessControlProof; // url, per-request status + body digest, owner/unauthorized labels
}
export type HeaderedFetchImpl = (url: string, headers: Record<string,string>) => Promise<{ status: number; body: string }>
export function runAccessControlChecks(identities: Identity[], fetchImpl: HeaderedFetchImpl): Promise<AccessControlOutcome[]>
```

Behind `runAccessControlChecks`: the empty (no-auth) identity is synthesized;
for each identity's private URL the owner is fetched (ground truth), then the
same URL is replayed as each other identity and as the no-auth control; response
bodies are normalized and digested; the oracle decides the outcome; the category
is selected; the proof is assembled with no body content. The `fetchImpl` seam is
injected (like `InjectionClass`'s confirmer and the SSRF-guarded `BodyFetchImpl`)
so the oracle is exercised without live sessions.

**`src/services/scanner.ts`** — `StartScanOptions` gains `identities?: Identity[]`
and `confirmIdentitiesAuthorized?: boolean`; active-mode scans carrying
identities validate the attestation, invoke `runAccessControlChecks` through the
SSRF-guarded fetch, and persist outcomes as findings.

## Implementation decisions

- **Confirmation is cross-identity replay only.** Parameter/id-tampering is
  rejected: it has no deterministic baseline (ADR 0002).
- **Three-way oracle per URL:** owner (ground truth), unauthorized peer, no-auth
  control. `idor` = peer digest == owner digest AND no-auth digest != owner
  digest. `unauthenticated-resource-access` = no-auth digest == owner digest on a
  declared-private URL. No-auth == owner with no access distinction = public =
  no finding.
- **The no-auth request does double duty:** negative control for `idor` and the
  probe for `unauthenticated-resource-access` — one request, both jobs.
- **Identities are opaque.** Headers are attached verbatim; Colossus never
  parses, refreshes, or drives a login flow to mint them.
- **Identities are ephemeral.** Supplied per scan, held only for its duration,
  never persisted — the deliberate inverse of durable enumerated hosts.
- **Ground-truth URLs are operator-declared per identity.** No crawl-as-identity.
- **Active mode only**, behind a **new identity-ownership attestation** layered
  on the existing active-mode attestation.
- **Two categories:** `idor`, `unauthenticated-resource-access` — distinct
  defects with distinct remediation, per the one-category-per-defect rule.
- **Evidence is digests + statuses + identity labels, never the private body.**
  Access-control findings suppress the evidence snippet.
- **A stale/failed ground-truth session is a reported scan error**, not
  re-authenticated around.

## Testing decisions

- **`access-control.ts`:** tested through `runAccessControlChecks` with a fake
  `HeaderedFetchImpl` mapping (url, headers) → (status, body). This is the seam
  that exercises the whole oracle — every branch (idor hit, unauthenticated hit,
  public/no-finding, stale-session error, identical-peer-but-public) is driven by
  fixture responses, no live sessions or network.
- **`scanner.ts`:** tested at its existing public scan seam — that an
  active-mode scan with identities and the attestation produces the expected
  findings, that a missing attestation is rejected, and that a passive-mode scan
  runs no access-control checks.
- **Deliberately untested:** digest-normalization internals and the synthesized
  no-auth identity are covered transitively through the oracle, not directly —
  they are module-private and have no meaning outside `runAccessControlChecks`.
- **Deliberately untested:** real session acquisition and login flows — out of
  scope, so there is nothing to test.

## Out of scope

- **Vertical privilege escalation** — needs a declared role ordering on the
  program that nothing models today; deferred to a later phase.
- **Parameter/id-tampering confirmation** — no deterministic baseline; rejected
  by doctrine (ADR 0002).
- **Colossus-driven login flows / credential-based auth** — an enormous,
  per-target-bespoke surface; identities are opaque session material instead.
- **Persisting identities** — live credentials are never stored at rest; they
  are ephemeral scan inputs.
- **Crawl-as-identity discovery** — would make the phase-3 crawler
  identity-aware; ground-truth URLs are operator-declared for now.
- **JWT / OAuth / SAML token & protocol inspection** — split into its own later
  phase; this phase is IDOR-first.
- **Passive-mode access-control checks** — replaying real sessions is an
  authenticated active action; passive-mode scans run none.
