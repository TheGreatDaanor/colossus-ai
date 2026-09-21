---
id: 046
title: Confirm horizontal IDOR by cross-identity replay
status: done
type: afk
blocked-by: []
---

## Slice

An operator starts an active-mode scan carrying two identities (each an
opaque header bundle plus a short list of URLs private to it) and the
identity-ownership attestation, and sees an `idor` finding in
`GET /scans/:id` when one identity's private resource is retrievable by the
other. This is the thick first slice: a new `access-control` service, a new
`findings` column, and the scanner wiring that makes both visible through the
existing scan API.

## User stories covered

- From PRD: attach one or more identities to an active-mode scan; a scan with
  no identities runs no access-control checks.
- From PRD: supply each identity as an opaque header bundle attached verbatim
  (Colossus never parses or modifies it).
- From PRD: declare per identity the URLs known to be private to it; no
  crawling occurs to find them.
- From PRD: an active-mode scan carrying identities is rejected unless the
  identity-ownership attestation is set (independent of the existing
  active-mode attestation).
- From PRD: get an `idor` finding when a peer identity receives another
  identity's private resource.
- From PRD: no finding when a resource returns the same content to everyone
  (public pages are not leaks).
- From PRD: a confirmed finding never contains the victim's private data —
  digest/status differential and identity labels only; `evidence_snippet` and
  `evidence_path` null.
- From PRD: supplied identities are discarded when the scan completes (never
  persisted).

## Layers touched

- Schema: `src/db/schema.ts` — add nullable `access_control_evidence` text
  column to `findings` (compact JSON: url, per-request status + normalized-body
  digest, owner and unauthorized identity labels; no response body). Regenerate
  the Drizzle migration; do not hand-edit `src/db/migrations/`.
- Service: NEW `src/services/access-control.ts` — `Identity`,
  `AccessControlOutcome`, `HeaderedFetchImpl`, and `runAccessControlChecks`.
  Synthesize the empty (no-auth) identity; for each identity's private URL
  fetch the owner (ground truth), replay as each peer and as the no-auth
  control, normalize + digest bodies, and apply the oracle: `idor` fires when
  a peer digest matches the owner digest AND the no-auth digest differs.
  Assemble the proof with no body content.
- Service: `src/services/scanner.ts` — `StartScanOptions` gains
  `identities?: Identity[]` and `confirmIdentitiesAuthorized?: boolean`;
  active-mode scans carrying identities validate the attestation and invoke
  `runAccessControlChecks` through the SSRF-guarded fetch; outcomes persist as
  findings. Identities are never written to the database.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass — the oracle is driven by a fake
  `HeaderedFetchImpl` mapping (url, headers) → (status, body): an `idor` hit
  (peer == owner, no-auth diverges), a public resource (no-auth == owner → no
  finding), and the persisted finding carrying `access_control_evidence` with
  `evidence_snippet`/`evidence_path` null.
- [x] Visible at: an active-mode scan started with two identities and the
  attestation reports an `idor` finding via `GET /scans/:id`; the same scan
  without the attestation is rejected.

## Out of scope

- The `unauthenticated-resource-access` category ([[047]]) — this slice
  records the no-auth control response but only fires `idor`.
- Stale/failed ground-truth session error handling ([[048]]).
- Vertical privilege escalation, param/id-tampering, login automation, and
  crawl-as-identity discovery — all out of scope for the phase (see PRD).
