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

## The key cannot be the category

Categories are **not unique per target**, and already are not, before [[018]]
and [[020]] add anything. [[016]] shipped `detectCookieFindings`, which emits
one finding per missing attribute *per cookie* — a target with three insecure
cookies produces three findings all carrying `category:
"cookie-missing-secure"`. Keying by category would collapse or misattribute
among them: the exact bug this issue exists to fix.

The key is a **synthetic per-finding id** (`f0`, `f1`, …) sent with each
finding in the prompt and echoed back by the model. Positional in origin, but
self-describing, so a reordered, short, or truncated response still lands
correctly — and it imposes no "every detector must produce a discriminator"
contract on future detectors.

Deduplicating to one finding per category (carrying a list of affected
cookies) would also make the key unique, and would simplify the model — but it
silently reverses [[016]], which shipped one issue ago specifically to get
per-cookie granularity.

## Enrichment must stop overwriting detector explanations

Related bug on the same code path: cookie findings already carry a precise,
factual `explanation` ("Cookie \"session\" is missing the Secure attribute"),
and the insert in `#processTarget` prefers the LLM's `explanation` over it.

Flip the precedence — the detector's `explanation` wins, the LLM fills only
where the detector left it null, and `suggestedFix` stays LLM-owned. A
detector's explanation is a fact about the response; the LLM's is a paraphrase
of a category name. This is a behavior change slightly beyond the keying
scope, carried here because it is three lines on the same code path.

## Layers touched

- Service: `src/services/scanner.ts` — prompt sends each finding with a
  synthetic id and asks for results keyed by it; unmatched keys are dropped,
  unmatched findings are stored with null enrichment; detector explanations
  take precedence over LLM ones.
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
