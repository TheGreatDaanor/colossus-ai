---
id: 020
title: Add body-derived passive checks (mixed content, form action, generator, listing)
status: done
type: afk
blocked-by: [019]
---

## Slice

The HTML a target returns is now inspected, producing findings for insecure
subresources, forms posting over plaintext, version-revealing generator
tags, and exposed directory listings.

## Checks and their categories

| Category | Trigger | Severity | Confidence |
|---|---|---|---|
| `mixed-content` | HTTPS page references `http://` script/style/iframe | medium | definitive |
| `insecure-form-action` | `<form action>` resolves to `http://` | high | definitive |
| `password-field-autocomplete` | `<input type=password>` without `autocomplete="new-password"`/`"current-password"` | low | possible |
| `directory-listing` | response matches an index-of listing shape | medium | possible |
| — | `<meta name=generator content="X 1.2.3">` | — | — |

The generator tag emits **no category of its own**: it feeds
`extractVersionBanner`, so a version found there flows into the existing
OSV correlation and surfaces as `known-vulnerability` like any other banner.
That keeps one CVE pathway rather than two.

## Layers touched

- Service: `src/services/passive-checks.ts` — pure detectors over the body
  threaded by [[019]].
- Service: `src/services/scanner.ts` — extend the banner source list so a
  generator-tag version reaches the existing OSV check.

## Parsing approach

Static inspection only, no headless browser (consistent with `ROADMAP.md`'s
phase-3 stance that HTML parsing needs no browser). Prefer a real HTML
parser over regex for attribute extraction; note this may mean a new
dependency — flag it in review rather than hand-rolling a tag matcher.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: a stubbed fetch returning a fixture HTML page with each
      defect produces each expected category exactly once, and a generator
      meta tag reaches OSV correlation.

## Out of scope

- Executing JavaScript or checking dynamically-inserted content.
- Secret/API-key scanning in HTML or inline scripts — worth its own issue;
  the false-positive design is a whole conversation.
- Following or fetching any referenced subresource — these checks read the
  markup, they do not request what it points at.
