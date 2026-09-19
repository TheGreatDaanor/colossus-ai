---
id: 012
title: Enforce SSRF guard on every in-browser navigation and redirect
status: done
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

## Extract the guard first — do not import it from `scanner.ts`

`scanner.ts` already imports `active-scanner.ts` (for
`enumerateInjectionPoints`). Exporting `findDisallowedAddress` *from*
`scanner.ts` for `active-scanner.ts` to use would close that into a cycle, and
an import cycle combined with Vitest module mocking produces failures that
read like logic bugs.

So `findDisallowedAddress` and the IP-range tables move to a new
`src/services/ssrf-guard.ts` that both modules import. This is the same move
[[017]] makes for the detectors, one issue earlier, and it makes the guard
independently testable — which matters more here than for anything else in the
file. It also removes the guard from the set of things [[017]] would otherwise
leave behind in `scanner.ts` under the heading of "orchestration", where it
does not belong.

## Layers touched

- Service: new `src/services/ssrf-guard.ts` — `findDisallowedAddress` and the
  IP-range constant tables, moved verbatim from `scanner.ts`.
- Service: `src/services/scanner.ts` — imports the guard from its new home.
- Service: `src/services/active-scanner.ts` — a `page.route()` /
  `page.on('request')` interception hook resolves each request's hostname and
  checks it against `findDisallowedAddress` before allowing it; a match aborts
  the request and marks the attempt `unavailable`.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: an active scan against a fixture page that issues a redirect (or makes a sub-request) to a private/loopback/link-local/metadata address never has that request reach the mocked network layer in tests; the attempt is recorded as `unavailable` with an explanatory error.

## Out of scope

- DNS rebinding between check-time and request-time — same accepted gap as
  [[002]], not closed here either.
- Emitting a **finding** for a target that redirects the scanner at a private
  address (`redirect-to-internal-address`, medium, definitive). A target doing
  this is genuinely interesting and this is a real candidate — but this issue
  is defensive: its job is that the scanner does not become the exploit, and
  turning it into a detector doubles its surface and its test matrix. Recorded
  here so it is not reinvented from scratch later.

