---
id: 051
title: Capture DNS callbacks and dedup DNS+HTTP hits to one finding
status: open
type: afk
blocked-by: [050]
---

## Slice

A blind SSRF that only triggers a DNS lookup of the injected token subdomain is
now confirmed, and a token that produces both a DNS and an HTTP hit yields a
single finding listing both protocols.

## User stories covered

- From PRD: blind SSRF caught via bare DNS resolution; one finding per (target, param) with
  DNS+HTTP pairs enriching the `protocols` set rather than duplicating.

## Layers touched

- Schema: `structured_evidence` ssrf variant `protocols` carries `['dns'|'http', ...]`.
- Service: `CollaboratorClient` hit model gains `protocol`; `ssrf-probe` confirms on
  a DNS-only hit and aggregates DNS+HTTP for one token into a single outcome.
- Route / UI: none new (protocols rendered by 056).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] Fake collaborator: DNS-only hit → finding; DNS+HTTP pair → one finding, both protocols
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active scan whose fake reports a DNS-only hit → `ssrf` finding

## Out of scope

- The real authoritative-DNS listener (055) — driven by a fake here
