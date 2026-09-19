---
id: 035
title: Probe each host's scheme and retain hosts that stop resolving
status: open
type: afk
blocked-by: [032]
---

## Slice

The inventory shows, for each live host, the URL it actually answers on —
HTTPS preferred, HTTP when that is all it has — and keeps hosts that have gone
dark rather than dropping them.

## User stories covered

- From PRD: each live in-scope host is probed for scheme.
- From PRD: a host that stops resolving is retained.

## Layers touched

- Schema: `enumerated_hosts.endpoint_url`, `last_resolved_at`,
  `failed_resolutions`.
- Service: `src/services/enumeration.ts` — `resolveEndpoint(hostname)` probing
  both schemes, keeping whichever responds and preferring HTTPS when both do;
  null when neither answers. Hosts are excluded from scanning after 3
  consecutive failed resolutions but keep their row and history, and remain
  eligible for takeover checks — NXDOMAIN on a still-CNAME'd host is itself
  the takeover signal.
- Route / UI: the inventory listing shows endpoint URL and dormant hosts.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `GET /programs/:id/hosts` shows `https://` for a host
      answering on both, `http://` for an HTTP-only host, and a dormant host
      retained with its `last_resolved_at` after 3 failures.

## Out of scope

- Spawning scan targets from these endpoints (037).
- Ports other than the scheme defaults.
