---
id: 039
title: Show which hosts appeared since last time
status: done
type: human
blocked-by: [032]
---

## Slice

An operator opens their program and can see at a glance which hosts are new —
the shadow-IT signal that justified making the inventory persistent.

`type: human` because the output is a view whose value is entirely in whether
a human can read it, and because it must present new hosts *without* implying
they are defects.

## User stories covered

- From PRD: I can see which hosts appeared since last time.

## Layers touched

- Schema: none — reads `enumerated_hosts.first_seen_at`.
- Service: a query grouping the inventory by first-seen against the previous
  enumeration.
- Route / UI: the program's inventory view, with new hosts distinguished.

## Definition of done

- [x] Failing test written first, confirmed red
- [x] Implementation makes it green
- [x] `test`, `typecheck`, `lint` all pass
- [x] Visible at: the program view after a second enumeration distinguishes
      hosts that appeared since the first; a human confirms new hosts do not
      read as findings.

The `type: human` half is done. An operator read the inventory view against a
real run and accepted it: `is_new` sits among the host's plain facts on
`GET /programs/:id/hosts`, with no severity, confidence or category anywhere
near it, alongside a top-level `new_since` naming the enumeration they appeared
after. `scripts/walkthrough.sh` reproduces the view the review was made against
— it creates a program, enumerates twice and scans, and `--simulate-new HOST`
plants a host between the enumerations so the second has one to mark.

The review also turned up a question the implementation does not settle, filed
as [041]: newness is read off the most recent distinct `first_seen_at`, and a
mid-scan crawl discovery writes one of those just as an enumeration does, so a
scan can change what reads as new without any enumeration having run.

## Out of scope

- Emitting a new host as a finding — rejected in the PRD: a finding category
  is the identity of a defect, and a new host is not one.
- Alerting or notification on change.
