---
id: 030
title: Detect a dangling CNAME for a single hostname
status: done
type: afk
blocked-by: []
---

## Slice

A human can run a command against any hostname and be told whether its CNAME
chain is dangling — the reference points at a provider resource that no longer
resolves.

Deliberately independent of the program model: takeover detection is a function
of a DNS name alone, so it can be built and proven in parallel with 029.

## User stories covered

- From PRD: a dangling CNAME with no fingerprint match produces a takeover
  finding at `possible` confidence.

## Layers touched

- Schema: none.
- Service: `src/services/takeover.ts` — `checkTakeover(hostname): Promise<TakeoverEvidence | null>`,
  resolving the CNAME chain and reporting the dangling target. Confidence is
  `possible` at this stage; the fingerprint upgrade is 031.
- Route / UI: a `scripts/` command that prints the evidence for one hostname.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: `npx tsx scripts/check-takeover.ts <hostname>` prints the
      dangling CNAME target, or reports the chain is healthy.

## Out of scope

- Provider fingerprints and `definitive` confidence (031).
- Persisting findings (036) — this issue only reports.
- Claiming the dangling resource — permanently out of scope per PRD.
- The resolver is stubbed in tests; no test performs live DNS.
