---
id: 012
title: Enforce SSRF guard on every in-browser navigation and redirect
status: open
type: afk
blocked-by: [011]
---

## Slice

Every navigation or redirect a Playwright page attempts during active
scanning is checked against the same disallowed-address guard used for
passive fetches; a request to a disallowed address is aborted and the
attempt is recorded as `unavailable` with an explanatory error — visible as
a redirect-to-`169.254.169.254` (or other private/loopback/link-local/
metadata address) during an active scan never reaching that address, and
the target's attempt outcome showing why.

## User stories covered

- From PRD: active scanning doesn't become a hole in my own SSRF
  protection.

## Layers touched

- Service: `src/services/active-scanner.ts` — a `page.route()` /
  `page.on('request')` interception hook resolves each request's hostname
  and checks it against the existing `findDisallowedAddress` (from
  `scanner.ts`, exported for reuse) before allowing it; a match aborts the
  request and marks the attempt `unavailable`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: an active scan against a fixture page that issues a redirect (or makes a sub-request) to a private/loopback/link-local/metadata address never has that request reach the mocked network layer in tests; the attempt is recorded as `unavailable` with an explanatory error.

## Out of scope

- DNS rebinding between check-time and request-time — same accepted gap as
  [[002]], not closed here either.
