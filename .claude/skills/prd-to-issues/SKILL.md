---
name: prd-to-issues
description: Split a PRD into independently grabbable kanban issues using vertical slices and tracer bullets. Use after write-a-prd, or when the user has a spec and wants it broken into tickets, tasks, or a backlog an agent can work through. Produces markdown issues with blocking relationships in issues/.
---

# PRD to issues

Turn the destination document into a **directed acyclic graph of grabbable issues** —
not a numbered phase plan.

A phase plan is a loop only one agent can walk. A board with explicit blocking
relationships lets several agents grab unblocked work at once.

## Step 1 — locate the PRD

Find `issues/PRD-*.md`. If this is a fresh context, also dispatch an exploration
sub-agent over the codebase so your slices match reality.

## Step 2 — cut vertical slices

**This is the whole skill. Get it right or the rest is worthless.**

You will be tempted to slice horizontally: one issue for all the schema, one for all
the services, one for all the UI. Do not. A horizontal plan produces no feedback
until the last layer lands, which means the agent codes blind for the entire middle
of the project.

Cut **tracer bullets** instead. Each issue crosses every layer it needs to —
schema *and* service *and* a visible surface — and ends in something a human can
look at.

Test each proposed slice against this: *what can a human see or do when this is
done, that they couldn't before?* If the answer is "nothing yet, it's groundwork",
the slice is horizontal. Re-cut it.

The first slice is the one that matters most. It should be thick — a real chunk of
schema, a real new service, and a minimal but genuine UI surface — because
everything after it becomes addition rather than integration.

Legitimate exceptions, which you must justify inline: pure dev-infrastructure work
(adding a test harness, a migration runner) and pure refactors that unblock the
first real slice.

## Step 3 — classify

Tag each issue:

- **`type: afk`** — an unattended agent can finish and verify this. Backend logic,
  schema, services, data transforms, tests.
- **`type: human`** — needs eyes or judgement. Anything where the output is visual,
  anything touching auth, payments, or destructive migrations, anything where
  "correct" is a matter of taste.

Be honest. A `human` issue mislabelled `afk` is how you get a green loop and a
broken product.

## Step 4 — wire the DAG

Set `blocked-by` to the minimum true set. Over-blocking silently serialises the
board and kills parallelism. Ask, for each edge: would this issue actually fail
to compile or fail its tests without the other one? If not, drop the edge.

## Step 5 — write the files

One file per issue at `issues/NNN-slug.md`, following `issues/_TEMPLATE.md` exactly.
Write them as **local markdown files**. Do not create GitHub issues, do not call
`gh`, unless the user explicitly asks.

## Step 6 — show the shape

Finish with the parallelism the board allows:

```
wave 1 (parallel):  001, 002
wave 2 (parallel):  003, 004   [after 001]
wave 3:             005        [after all]
```

If wave 1 has one issue in it, your DAG is a chain — go back to step 4 and check
whether those edges are real.
