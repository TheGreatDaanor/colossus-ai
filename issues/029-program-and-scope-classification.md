---
id: 029
title: Create a program with scope lists and classify hosts against them
status: open
type: afk
blocked-by: []
---

## Slice

An operator can POST a URL, get back a program with its apex seeded into the
in-scope list, edit both lists, and ask the API how any hostname classifies —
`in_scope`, `out_of_scope` or `unscoped`.

This is the thick first slice: it establishes the program, the scope grammar,
and the classification rule that every later issue depends on.

## User stories covered

- From PRD: I can create a program with in-scope and out-of-scope lists.
- From PRD: creating a program from a submitted URL seeds its apex.
- From PRD: subdomains of an in-scope apex are in scope by default.
- From PRD: I can put an exact host in scope without its apex.
- From PRD: an out-of-scope entry always wins.
- From PRD: hosts matching neither list classify as `unscoped`.

## Layers touched

- Schema: `programs`, `scope_entries` (with `confirmed_at`, written but not yet
  enforced — enforcement is 033).
- Service: `src/services/programs.ts` — apex computation via the Public Suffix
  List, and `classifyHost(hostname, scope): ScopeStatus` as one ordered rule,
  out-of-scope evaluated first.
- Route: `src/routes/programs.ts` — create (seeding apex from a URL), read,
  add/remove scope entries, and a classification endpoint.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `POST /programs {"url":"https://example.com/x"}` returns a
      program with `example.com` in scope; `GET /programs/:id/classify?host=vpn.internal.example.com`
      returns `out_of_scope` once `*.internal.example.com` is excluded.

## Out of scope

- Enumeration of any kind (032).
- Enforcing `confirmed_at` before enumeration (033).
- URL path prefixes and CIDR ranges in the scope grammar — deferred per PRD.
