---
id: 052
title: Escalate to critical on response-based internal-read signature match
status: open
type: afk
blocked-by: [050]
---

## Slice

An active scan whose target reflects internal content from a fixed internal-target
payload (AWS IMDSv1 metadata) matching a known signature yields a `critical`
`ssrf` finding tagged `internal-read`, above the `high` OOB tier.

## User stories covered

- From PRD: response-based secondary signal; two-tier severity (high OOB /
  critical internal-read); confidence always definitive; an echoed payload is
  never an internal read; one finding per (target, param) at the highest tier.

## Layers touched

- Schema: `structured_evidence` ssrf variant `tier: 'internal-read'` + `matchedSignature`.
- Service: `ssrf-probe` fires `169.254.169.254/latest/meta-data/` per param and
  matches the metadata listing's line-set signature (never a substring of the
  payload). A match confirms `critical` on its own, with or without an OOB
  callback; when both fire, one finding at tier `internal-read`, carrying both
  protocols and signature. Writes an `internal-read` attempt only on a match; a miss writes no row
  (never `not_vulnerable`) and adds `internalRead: 'not-demonstrated'` to any
  `oob` finding for that param.
  Body-free (no response body stored).
- Route / UI: none new (tier/signature rendered by 056).

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] Signature match → critical, with or without OOB; no match → stays high/OOB;
      no false-positive on bare 200 or on a response echoing the payload
- [ ] OOB + internal-read on one param → exactly one finding
- [ ] No match → no `internal-read` attempt row; OOB finding carries
      `internalRead: 'not-demonstrated'`
- [ ] A 401/400 or empty body from the metadata payload → no signal
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: active scan reflecting a metadata signature → `critical` `ssrf` finding

## Out of scope

- Escalating unfingerprintable internal reads (stays high)
- `localhost`, IMDSv2, GCP and Azure metadata (not confirmable by a forged fetch)
- Non-http schemes
