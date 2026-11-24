---
status: accepted
---

# A self-hosted collaborator for out-of-band SSRF confirmation

Phase 6 (SSRF exploitation) confirms a defect when the **target's own server**
contacts a host Colossus controls, carrying a token Colossus injected. That
needs a **collaborator**: a public host that answers DNS for its own zone,
accepts HTTP, and can be asked which tokens reached it. We decided that the
collaborator is **self-hosted: one standalone listener daemon per Colossus
deployment**. It is the authoritative nameserver for an NS-delegated zone,
records DNS and HTTP callbacks by token in a bounded in-memory buffer, and
exposes them through a query API guarded by a shared secret. Scan code reaches
it only through the injected `CollaboratorClient` seam.

## Considered options

- **Third-party OAST service (Burp Collaborator, public interactsh).**
  Rejected. Confirmation would depend on an oracle Colossus does not control:
  its availability, retention and rate limits decide whether a scan's verdict
  is final. Every injected token, plus the target's caller IP, would also leak
  to an outside party. Burp Collaborator additionally ties Colossus to a
  commercial product it does not otherwise use.
- **A self-hosted interactsh server.** Rejected for now. It is viable, but it
  brings a third-party protocol and client (encrypted polling, its own token
  format) to replace a listener whose logic is trivial: record a hit by token.
  The seam leaves this open as a drop-in `CollaboratorClient` implementation.
- **One listener per program or per operator.** Rejected. Isolating scans at
  the network level adds deploy surface for no gain, because globally unique
  tokens already prevent a callback from being attributed to the wrong scan.
- **No out-of-band confirmation (response-based or timing-based only).**
  Rejected. Blind SSRF, the common case, never shows in the response, and
  timing has no deterministic baseline. That conflicts with the confirmed-only
  doctrine.

## Consequences

- Deploying Colossus now involves **separate infrastructure**: a public IP, an
  authoritative DNS server, and a one-time NS delegation of the collaborator
  zone, documented as a runbook step. Base domain, query URL and secret are
  deploy configuration and are never accepted per scan.
- A deployment without it is still valid. SSRF reports as `unavailable` with a
  reason, never as clean. The preflight's self-callback proves the whole path
  works (DNS delegation, HTTP listener and query API) before any payload is fired.
- The listener's socket I/O is **not unit-tested**. Every confirmation branch is
  tested against a fake `CollaboratorClient`. A bug that lives only in the
  listener's DNS parsing escapes the tests, the same accepted gap as the real
  Chromium path.
- Callbacks live in memory with a ~10 minute TTL and are never persisted. This
  works because each scan resolves its verdicts in a single bounded drain
  window. Late or deferred reconciliation would need durable callback storage
  and a revisit of this decision.
- The shared secret is rotated **manually on redeploy**. It guards an internal
  query API, not a public surface.
