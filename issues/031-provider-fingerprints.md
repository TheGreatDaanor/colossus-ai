---
id: 031
title: Upgrade takeover evidence to definitive with provider fingerprints
status: open
type: afk
blocked-by: [030]
---

## Slice

The takeover command now names the provider and reports `definitive`
confidence when the provider's own response confirms the resource is
unclaimed, instead of only saying the CNAME is dangling.

## User stories covered

- From PRD: a dangling CNAME whose provider response matches a known unclaimed
  fingerprint produces a takeover finding at `definitive` confidence.
- From PRD: Colossus never claims the dangling resource — remediation text
  names the provider and resource instead.

## Layers touched

- Schema: none.
- Service: `src/services/takeover.ts` — a hand-maintained in-repo fingerprint
  table (S3, GitHub Pages, Heroku, Azure, Fastly, Shopify to start), the HTTP
  fetch that matches it, and the remediation text.
- Route / UI: the 030 command prints provider, confidence and remediation.

## Definition of done

- [ ] Failing test written first, confirmed red
- [ ] Implementation makes it green
- [ ] `test`, `typecheck`, `lint` all pass
- [ ] Visible at: `npx tsx scripts/check-takeover.ts <hostname>` prints
      `definitive` plus the provider for a fingerprinted host, and `possible`
      for a dangling host with no fingerprint match.

## Out of scope

- Fetching the fingerprint list at runtime — rejected in the PRD: a third
  party must not be able to change what Colossus asserts as `definitive`.
- Providers beyond the initial six; the table grows on demand.
