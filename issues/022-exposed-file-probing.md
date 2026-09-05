---
id: 022
title: Probe a small fixed wordlist for exposed sensitive files
status: done
type: human
blocked-by: []
---

## Slice

Each target is checked for a handful of commonly-exposed paths — `/.git/HEAD`,
`/.env`, `/server-status`, `/.well-known/security.txt` — producing findings
when they are reachable.

## Why this is passive

Per [[CONTEXT]], a passive check is one that sends no payload designed to
trigger a vulnerability. These are ordinary GETs for ordinary paths, so they
run in passive mode and need no authorization attestation — the attestation
gate exists for payload-sending active checks. The scanner already makes an
unsubmitted request of this shape (`robots.txt`, for banner detection).

## Deliberately parked

Cut now so the decision is recorded rather than silently reinvented, but not
scheduled: unlike [[018]] and [[020]], this introduces per-target request
fan-out and therefore needs a request budget that does not exist yet.

That budget is **not** [[013]]'s. [[013]] caps concurrent *browser contexts*
in active mode; this needs a per-target *HTTP request* allowance in passive
mode, where several extra GETs per target multiply against the existing
concurrency of 10. Different resource. This issue defines its own, below.

## Request fan-out budget (defined here)

- A per-target request allowance — `maxExtraRequests`, default ~6 — covering
  every request beyond the target's primary fetch.
- Enforced in one small helper, so [[014]]'s crawl (same fan-out shape, same
  need, capped at 25 discovered pages) reuses it rather than inventing a
  second bound.
- A global in-flight semaphore would protect the machine but not the *target*,
  which is the party there is an attestation with. The allowance is per-target
  for that reason.

## Checks and their categories

| Category | Trigger | Severity | Confidence |
|---|---|---|---|
| `exposed-git-directory` | `/.git/HEAD` returns 200 with `ref:` content | critical | definitive |
| `exposed-env-file` | `/.env` returns 200 with env-shaped content | critical | definitive |
| `exposed-server-status` | `/server-status` returns 200 | medium | definitive |
| `security-txt-present` | `/.well-known/security.txt` returns 200 | info | definitive |

Content shape matters, not just status: a site returning a 200 SPA shell for
every unknown path would otherwise report `exposed-env-file` on every
target. `security-txt-present` is an `info` finding recording something
*good* — the first of its kind in the codebase; confirm the dashboard renders
it sensibly rather than as an alarm.

## Bounds

- Fixed wordlist, single digits. This is a fetch, not a content-discovery
  scan; growing the list is a new conversation.
- Probes respect the same SSRF guard, user-agent, and timeout handling as the
  primary fetch.

## Definition of done

- [x] Per-target request allowance implemented as described above
- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `lint` pass; `typecheck` has 4 pre-existing TS7006
      errors in `scanner.test.ts` unrelated to this issue
- [x] Visible at: a stubbed fetch serving `/.env` produces
      `exposed-env-file`; a stub returning 200 HTML for every path produces
      none.

## Out of scope

- Any wordlist worth the name — no `dirb`/`SecLists`-scale enumeration.
- Downloading or parsing the contents of an exposed `.git` directory.

## Decisions taken at implementation time

- **Unparked on request.** This issue was cut as "not scheduled"; it was pulled
  forward deliberately. The blocker it named - the missing request budget - is
  defined by the issue itself and is implemented here, so nothing was owed.
- **`Budget` is one helper with two instances**, per the issue's "one small
  helper" requirement: a per-target allowance of `maxExtraRequests` (default 6,
  covering robots.txt and the four probes) and the per-root cap of 25 discovered
  pages that [[014]] previously counted inline. They bound different resources
  and so hold different limits; retrofitting [[014]] changed no behaviour.
- **`/server-status` and `security.txt` got content-shape tests** the table did
  not ask for. The table triggers them on status 200 alone, but the DoD requires
  that a site answering every path with a 200 HTML shell produces no findings -
  status alone cannot satisfy both. `security.txt` requires RFC 9116's mandatory
  `Contact:` field; `/server-status` requires "server status" in the body.
- `Budget` lives in `scanner.ts`, not a new module: at ~15 lines it is exactly
  the shallow module `CLAUDE.md` says to avoid, and both callers are here.
- The dashboard renders findings as an unstyled table with no severity colouring,
  so the `info`-severity `security-txt-present` shows as an ordinary row and not
  as an alarm. No dashboard change was needed.
