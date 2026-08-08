---
id: 002
title: Reject targets on private/loopback/link-local/metadata IPs (SSRF guard)
status: open
type: afk
blocked-by: [001]
---

## Slice

A submitted URL whose hostname resolves to a private, loopback, link-local,
or metadata-service address (IPv4 or IPv6) is rejected before any fetch is
attempted — visible as that target's status becoming `invalid` with an
explanatory error in `GET /scans/:id`, instead of the scanner touching the
operator's internal network.

## User stories covered

- From PRD: protected from accidentally probing my own internal network —
  private/loopback/link-local/metadata hostnames rejected before fetching,
  covering both IPv4 and IPv6.

## Layers touched

- Service: `src/services/scanner.ts` — a pure `isDisallowedAddress(ip)`
  function covering private, loopback, link-local, and metadata ranges for
  both IPv4 and IPv6; the per-target pipeline from [[001]] resolves the
  hostname and checks it against this function before fetching.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `curl -X POST localhost:PORT/scans -d '{"urls":["http://127.0.0.1","http://169.254.169.254"]}'` then `curl localhost:PORT/scans/:id` (or `http://localhost:PORT/dashboard/scans/:id` in a browser, using the dashboard from [[001]]) shows both targets with `status: "invalid"` and an explanatory `error`, and the injected fetch mock in tests asserts it was never called for those targets.

## Out of scope

- DNS rebinding (safe at check-time, malicious at fetch-time) — accepted,
  hard-to-close gap per the PRD, not addressed here or anywhere in v1.
- Live DNS resolution behavior — deliberately untested per the PRD; only the
  pure IP-range classifier is unit-tested.
