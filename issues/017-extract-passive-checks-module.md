---
id: 017
title: Extract pure passive detectors into src/services/passive-checks.ts
status: open
type: afk
blocked-by: [016]
---

## Slice

Behavior-neutral refactor: every passive detector becomes a pure function in
a new `src/services/passive-checks.ts`, and `scanner.ts` keeps only
orchestration, fetching, and the SSRF guard. No finding changes.

## Why a new module rather than deepening scanner.ts

`CLAUDE.md` says prefer deepening an existing module over adding a shallow
one. `scanner.ts` is ~714 lines mixing SSRF guarding, IP-range arithmetic,
TLS, OSV correlation, LLM enrichment, and orchestration; [[018]] and [[020]]
add roughly a dozen more detectors to it. Extracting *narrows the
interface* — `passive-checks.ts` takes response data and returns findings,
performs no I/O, and needs no mocks to test. That's a deep module, not a
shallow one. It also matches the boundary `ROADMAP.md` already committed to
for `discovery.ts` and `active-scanner.ts`.

Per [[CONTEXT]], `passive-checks.ts` must not import from
`active-scanner.ts` in either direction: mode selects which detector sets
run, and the passive/active split only holds if the code reflects it.

## Layers touched

- Service: new `src/services/passive-checks.ts` — moves
  `detectHeaderFindings`, `detectTlsFindings`, `extractVersionBanner`,
  `isCookieSecure`'s replacement from [[016]], and the associated constant
  tables.
- Service: `src/services/scanner.ts` — imports them; re-exports any symbol
  currently imported elsewhere so no caller breaks.
- Tests: move the corresponding cases into
  `src/services/passive-checks.test.ts`.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `npx vitest run src/services` is green with no test
      *assertions* changed — only their file location. A diff review shows
      no behavioral change.

## Out of scope

- Adding any new check (that is [[018]] and [[020]]).
- Touching the SSRF guard, OSV correlation, or LLM enrichment internals —
  they stay in `scanner.ts`; only [[021]] changes enrichment.
