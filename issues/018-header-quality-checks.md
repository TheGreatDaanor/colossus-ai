---
id: 018
title: Detect present-but-weak security headers (CSP, HSTS, CORS, disclosure)
status: open
type: human
blocked-by: [017]
---

## Slice

A target that sets security headers *badly* — a CSP with `unsafe-inline`, an
HSTS with a two-minute `max-age`, a wildcard CORS policy alongside
credentials — now produces findings, where today setting the header at all
is enough to pass.

## Why this is `type: human`

Per `issues/README.md`, judgement calls need eyes. The severity and
confidence assignments below are exactly that: a report-only CSP or a
deliberately permissive CORS policy on a public API are both legitimate, and
the line between "weak" and "intentional" is a security judgement, not a
mechanical one. Review the table before the implementation is trusted.

## Checks and their categories

Per [[CONTEXT]], `confidence` grades the certainty of the *observation*, not
of exploitability — so contextual defects are `possible` while still being
definitely present.

| Category | Trigger | Severity | Confidence |
|---|---|---|---|
| `weak-csp-unsafe-inline` | `script-src`/`default-src` contains `unsafe-inline` | high | possible |
| `weak-csp-unsafe-eval` | contains `unsafe-eval` | medium | possible |
| `weak-csp-wildcard-default-src` | `default-src *` | high | possible |
| `weak-csp-missing-frame-ancestors` | no `frame-ancestors` directive | low | possible |
| `csp-report-only-only` | `Content-Security-Policy-Report-Only` present, enforcing CSP absent | medium | possible |
| `weak-hsts-short-max-age` | `max-age` < 15552000 (180d) | medium | definitive |
| `weak-hsts-no-subdomains` | no `includeSubDomains` | low | definitive |
| `permissive-cors-credentialed` | `Allow-Origin: *` or reflected, **with** `Allow-Credentials: true` | high | definitive |
| `permissive-cors-wildcard` | `Allow-Origin: *` without credentials | low | possible |
| `information-disclosure-header` | `Server`/`X-Powered-By`/`X-AspNet-Version` reveals software | low | definitive |

`csp-report-only-only` interacts with the existing `missing-csp`: a target
with only a report-only policy should emit **both**, since the enforcing
policy genuinely is missing.

## User stories covered

- From PRD: as the operator, I can see which security response headers are
  missing on each target — extended to headers that are present but do not
  provide the protection their presence implies.

## Layers touched

- Service: `src/services/passive-checks.ts` — new pure detectors over the
  existing header record. No new requests, no body needed.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Severity/confidence table above reviewed by a human
- [ ] Visible at: a stubbed fetch returning a realistic weak header set
      produces each expected category exactly once; `curl
      localhost:PORT/scans/:id` shows them with correct severities.

## Out of scope

- Parsing CSP into a full directive model — string/directive inspection is
  enough for these checks.
- Validating CSP hashes or nonces.
- Any check needing the response body ([[020]]).
