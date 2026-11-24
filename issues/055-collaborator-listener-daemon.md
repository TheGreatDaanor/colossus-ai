---
id: 055
title: Stand up the real self-hosted collaborator listener daemon
status: open
type: human
blocked-by: [050]
---

## Slice

A real deployed listener captures genuine DNS and HTTP callbacks from a live target
and, through the real `CollaboratorClient`, turns them into `ssrf` findings — the
same flow 050 proved with a fake, now on real infrastructure.

<!-- human: standalone network daemon, authoritative DNS, a shared auth secret, and
deployment/NS-delegation — largely un-unit-tested I/O, like the real-browser path. -->

## User stories covered

- From PRD: self-hosted collaborator behind the seam; DNS+HTTP capture;
  deploy-config (base domain, query URL, secret); one shared listener per deployment;
  manual secret rotation.

## Layers touched

- Schema: none.
- Service: NEW standalone daemon (outside `src/services`) — authoritative DNS for the
  NS-delegated zone + HTTP listener; bounded in-memory hit buffer (~10 min TTL);
  shared-secret-guarded internal HTTP query API. Real `CollaboratorClient` impl
  polling that API. Deploy config read at startup; absent → SSRF unavailable (053).
- Route / UI: operator runbook for NS-delegation and deploy config.

## Definition of done

- [ ] Failing test written first for the real CollaboratorClient (against a stub query API)
- [ ] Implementation makes it green
- [ ] Listener records DNS + HTTP hits by token; query API requires the secret
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: point a real target at the deployed listener → real callback → `ssrf` finding
- [ ] NS-delegation + deploy-config runbook written

## Out of scope

- Automated secret rotation; per-program/per-operator listeners; third-party OAST
- Unit-testing the raw DNS/HTTP socket internals (deliberate integration gap)
