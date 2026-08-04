---
id: 004
title: Surface TLS-outdated, cert-expiring, and no-TLS findings
status: open
type: afk
blocked-by: [001]
---

## Slice

A target on TLS below 1.2, with a certificate expiring within 30 days, or
served over plain `http://`, now shows a corresponding Finding, and
`tls_version`/`tls_cert_expires_at` are populated on the scan target.

## User stories covered

- From PRD: see if a target's TLS is outdated or its certificate is expiring
  soon — TLS protocol below 1.2 and certs expiring within 30 days each
  produce a Finding; plain-`http://` targets produce a "no TLS" Finding
  instead and skip the deeper cert/protocol checks.

## Layers touched

- Service: `src/services/scanner.ts` — TLS handshake check as a mockable seam
  (per the PRD's testing decisions — no real sockets in tests), feeding
  `tls_version`/`tls_cert_expires_at` onto the scan target and Finding rows
  into the pipeline from [[001]]. `http://` targets get a High "no TLS"
  Finding and skip the protocol/cert checks entirely.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: scan three mocked targets (TLS 1.0, cert expiring in 10
      days, plain `http://`) → `curl localhost:PORT/scans/:id` shows each
      target's corresponding Finding and populated `tls_version`/
      `tls_cert_expires_at` where applicable.

## Out of scope

- Header/cookie findings — [[003]].
- CVE findings — [[005]].
