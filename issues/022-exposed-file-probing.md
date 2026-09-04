---
id: 022
title: Probe a small fixed wordlist for exposed sensitive files
status: open
type: human
blocked-by: [017]
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

- [ ] Per-target request allowance implemented as described above
- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a stubbed fetch serving `/.env` produces
      `exposed-env-file`; a stub returning 200 HTML for every path produces
      none.

## Out of scope

- Any wordlist worth the name — no `dirb`/`SecLists`-scale enumeration.
- Downloading or parsing the contents of an exposed `.git` directory.
