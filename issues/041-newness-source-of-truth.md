---
id: 041
title: Decide whether a crawl discovery counts as appearing since last time
status: open
type: human
blocked-by: [039]
---

## Slice

An operator reading the inventory can tell what "since last time" is measured
against, and a scan running does not silently change which hosts read as new.

`type: human` because the question is what the phrase should mean to an
operator, not how to compute it. Both behaviours are cheap to implement; the
decision is which one is honest.

## The problem

Newness is derived from the distinct `firstSeenAt` values in the inventory —
the most recent value is the run that found something, and hosts carrying it
are marked `is_new`. Enumeration is not the only thing that writes that column.
Since [038] a scan's crawler records in-scope hosts it discovers, stamping them
the same way.

Observed on a real run (see `scripts/walkthrough.sh`): a host planted between
two enumerations was *not* the one marked. `iana.org`, which the scan's crawler
found after both enumerations had finished, was — because its `firstSeenAt` was
the newest distinct value. `new_since` moved with it.

Two consequences:

- A scan can change what the operator sees as new without any enumeration
  having run. The top-level `new_since` then names a moment that was not an
  enumeration, which is what the field's own route comment says it is.
- The set is all-or-nothing per timestamp. A crawl discovery displaces whatever
  the previous enumeration marked, rather than adding to it.

A crawl now stamps every host it finds with one time for the whole run, so a
scan counts as at most one "run" rather than one per page walked. That bounds
the problem but does not settle it: one scan still displaces the enumeration
before it.

## The decision

Not which is easier — which is true to "hosts that appeared since last time":

1. **Enumeration is the clock.** Only an enumeration defines a "last time";
   crawl-discovered hosts are recorded but never drive `new_since`. Keeps the
   field meaning what its comment claims. Costs: a genuinely new host found by
   the crawler does not read as new until the next enumeration.
2. **Any discovery is the clock.** Current behaviour, made deliberate and
   documented. A host new to the inventory is new however it was found. Costs:
   `new_since` is not an enumeration time, and running a scan reshuffles the
   view.
3. **Separate the two.** The host keeps how it was found (`source` already
   carries `ct-log` vs `crawl`) and the view distinguishes "new from
   enumeration" from "found while crawling".

Worth noting for whoever picks: on the observed run the crawl-discovered host
was `unscoped` and off the program's own domain — the shadow-IT shape the PRD
wanted. Option 1 would have hidden it until the next enumeration.

## Layers touched

- Schema: none for options 1–2. Option 3 may want the view to read `source`.
- Service: `listInventory` in `src/services/programs.ts` — where the distinct
  `firstSeenAt` values are reduced to a newest set.
- Route / UI: `new_since` on `GET /programs/:id/hosts`, and its comment in
  `src/routes/programs.ts`, which currently asserts option 1's meaning.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `./scripts/walkthrough.sh --simulate-new HOST` — after a scan
      has crawled, the inventory view agrees with whichever rule was chosen,
      and `new_since` names a moment the operator can account for.

## Out of scope

- Emitting a new host as a finding — still rejected, per [039] and the PRD.
- Alerting on change.
