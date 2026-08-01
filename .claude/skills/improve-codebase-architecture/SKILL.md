---
name: improve-codebase-architecture
description: Scan a codebase for shallow modules that should be merged into deep modules with small interfaces, ranked by testability gain. Use when the user asks how to improve code architecture, why agents perform badly in a repo, what to refactor, where tests are missing, or before starting agentic work in an unfamiliar or messy codebase.
---

# Improve codebase architecture

Find where this codebase is **shallow** and propose making it **deep**.

## The distinction

A **deep module** exposes a small interface and hides substantial functionality
behind it. A **shallow module** exposes almost as much as it contains — a file with
one exported function, a class that's a bag of getters, a "utils" module everything
imports.

Shallow module sets are bad for agents in two compounding ways:

1. **Navigation.** The dependency graph is wide and flat, so understanding any
   behaviour means walking a dozen files. That burns context before work starts.
2. **Testing.** There is no natural seam, so tests get drawn around individual
   functions and everything else gets mocked. Those tests verify structure, not
   behaviour — they stay green while the integration between the pieces is broken.

Since the quality of the feedback loop is the ceiling on agent output quality,
shallow modules cap how well any agent can ever do in this repo.

Unsupervised AI produces shallow modules by default. Assume drift.

## What to do

1. **Survey.** Map the modules, their exports, and their import edges. Use
   sub-agents for the file reading — return findings, not file contents.

2. **Find clusters.** Look for groups of modules that are always imported together,
   only imported by each other, or that change together in git history
   (`git log --name-only` over the last few hundred commits is a good signal).
   These are one module wearing several files as a disguise.

3. **Find the seams.** For each cluster, ask: is there a single interface that
   could front all of it? What would the caller need to know? If the answer is
   "three functions and a type", that's a deep module waiting to be extracted.

4. **Score by testability gain.** Rank candidates by: current test coverage of the
   cluster (lower is a bigger win) × how much behaviour sits behind the proposed
   interface × how central it is. The best candidate is usually a critical,
   untested, widely-imported cluster.

5. **Check for the big one.** Look for a subsystem that spans front end to back end
   and currently has no end-to-end seam at all — an editor, a wizard, a checkout
   flow. Wrapping one of these in a single testable module, so a test can drive it
   from the outside edge through to the data layer, is usually the single largest
   available improvement. Agents go from hopeless to competent in that subsystem.

## Output

For each candidate, in priority order:

```
### <N>. <Proposed module name>

Files to merge:      <list>
Proposed interface:  <3–5 signatures>
Why they're coupled: <the evidence — shared imports, co-change, shared state>
Current coverage:    <what tests exist today, honestly>
Testability gain:    <what a test could assert after, that it cannot assert now>
Dependency category: <local / substitutable-in-test / external>
Risk:                <what could break, what's load-bearing>
Effort:              <rough>
```

Then stop. Do not start refactoring. Propose, let the user pick, and turn the
chosen ones into issues.

## Constraints

- Do not propose a rewrite. Every candidate must be an incremental merge that
  leaves the codebase working at each step.
- Do not propose new abstraction layers, base classes, or plugin systems. Deepening
  means *hiding* complexity behind an existing boundary, not adding a boundary.
- If the codebase is already deep, say so plainly and stop. Do not manufacture work.
