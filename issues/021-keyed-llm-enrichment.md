---
id: 021
title: Key LLM enrichment responses by category instead of array position
status: open
type: afk
blocked-by: [017]
---

## Slice

Enrichment results are matched to findings by category rather than by
position in the returned array, so a short, reordered, or truncated LLM
response leaves findings *unenriched* instead of *wrongly enriched*.

## Why now

`#enrichFindings` sends a target's pending findings in one call and
positionally matches the response back. Today that is ~6 findings; after
[[018]] and [[020]] a single bad target realistically produces 15-20. The
longer the response, the likelier it comes back misaligned or truncated —
and positional matching has no key with which to recover, so the HSTS
suggested fix silently lands on the CORS finding. Mislabeled remediation
advice is worse than absent remediation advice.

## Change of shipped behavior

This modifies the enrichment contract established by [[006]]. Existing
`findings` rows keep their stored `explanation`/`suggestedFix`, so there is
no migration. Before implementing, confirm nothing outside
`src/services/scanner.ts` relies on the positional-array assumption —
check, do not assume.

## Layers touched

- Service: `src/services/scanner.ts` — prompt asks for an object/array keyed
  by finding category; unmatched keys are dropped, unmatched findings are
  stored with null enrichment.
- Schema: none. `explanation`/`suggestedFix` are already nullable.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: a stubbed LLM returning enrichment for a *subset* of
      findings, in the wrong order, enriches exactly those findings
      correctly and leaves the rest null — where the current code would
      misattribute them.

## Out of scope

- Chunking or capping batch size — cost is bounded and already cached; this
  issue is about correctness, not spend.
- Changing the enrichment prompt's wording beyond what keying requires.
- Re-enriching historical findings.
