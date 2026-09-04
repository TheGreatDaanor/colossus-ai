---
id: 019
title: Thread the response body through the passive pipeline, in memory only
status: open
type: afk
blocked-by: [017]
---

## Slice

Infrastructure slice: each target's fetched response body is read once, passed
to the passive detectors, and discarded. Nothing is persisted and no new
finding is produced — this exists so [[020]] has something to check.

## Why in-memory and not stored

Persisting response bodies is a real storage, size, and PII decision that
belongs to [[013]]'s evidence storage, and nothing in the body-derived check
set needs the body after its detectors have run. Holding it for the duration
of one target's checks keeps this slice free of schema change.

## The boundary carries a parsed document, not a raw string

Three consumers want this body: [[020]]'s tag and attribute checks, the
generator-tag banner path, and later [[014]]'s link and form harvesting. Each
re-parsing the same (up to 2 MB, hostile) string is waste, so the detector
boundary receives an already-parsed document.

Parser: **`cheerio`**. Every consumer here is doing selector-and-attribute
extraction — `$('form[action]')`, `$('meta[name=generator]')`,
`$('script[src]')` — and cheerio is `parse5` underneath, so this is
spec-compliant parsing with the ergonomic layer on top. `parse5` alone means
hand-walking the tree in every detector; `jsdom` is a full DOM over hostile
input, which is exactly the cost the size bound below exists to avoid.

The parser dependency therefore lands here, in [[019]], rather than in
[[020]] where it was originally flagged.

## Layers touched

- Dependency: add `cheerio`.
- Service: `src/services/scanner.ts` — read the body (bounded; see below)
  after the existing header handling, parse it once, and hand the document to
  the detector call.
- Service: `src/services/passive-checks.ts` — detector signature accepts an
  optional parsed document alongside headers.
- Schema: none, deliberately.

## Bounds

- Read at most 2 MB; beyond that, truncate and run detectors on the prefix.
  A body-derived check is best-effort, and an unbounded read is a
  memory-exhaustion vector on a hostile target.
- A body that fails to read (connection reset mid-stream, non-text content
  type) degrades gracefully: the target stays `ok`, header/TLS findings are
  unaffected, and body-derived checks are skipped — matching how the
  existing TLS-check failure path already behaves.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a test asserts the body reaches the detector boundary, that
      an oversized body is truncated, and that a mid-stream failure leaves
      header findings intact.

## Out of scope

- Storing the body in `scan_targets` or anywhere else — [[013]].
- Parsing links or forms out of it — that is [[014]]'s discovery work, which
  will consume this same threading.
- Any actual body-derived check ([[020]]).
