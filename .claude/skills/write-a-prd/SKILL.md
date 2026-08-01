---
name: write-a-prd
description: Write a product requirements document — the destination document — from a completed grilling session. Use after grill-me has established shared understanding, or when the user asks for a PRD, spec, or requirements doc for a feature. Produces problem, solution, user stories, implementation decisions, testing decisions, and out-of-scope.
---

# Write a PRD

The PRD is the **destination document**. It says where we're going, not how we get
there. The journey is the kanban board, and that's a different skill.

## Step 1 — check you have enough

You need a grilling session in this context. If you don't have one, stop and ask the
user for a long, detailed description of the problem, or suggest running `grill-me`
first. Do not invent requirements to fill gaps.

## Step 2 — propose the module map, and wait

Before writing anything, list the modules you intend to create or modify:

```
NEW      GamificationService   — points, levels, streak calculation
MODIFY   ProgressService       — emit completion events
MODIFY   dashboard route       — render points + level
```

For each new module, state its **public interface** in three lines or fewer.

Then stop and ask for approval. This is the one part of the PRD the user will
actually read, because it's the part that determines whether the codebase ends up
with deep modules or a scatter of shallow ones.

Bias hard toward **deep modules**: a small interface with substantial functionality
behind it. If your map has five new files each exporting one function, you have
designed a shallow module set — merge them and propose again.

## Step 3 — write the document

Write to `issues/PRD-<slug>.md`. Use exactly these sections:

```markdown
# <Feature name>

## Problem
The problem the user is facing. Two or three sentences. No solution language.

## Solution
What we're building, in prose. One paragraph.

## User stories
- As a <role>, I can <action>, so that <outcome>.
  - Acceptance: <observable condition>
(one per capability; expect 10–20)

## Data model
Tables/entities added or changed, with column types and nullability.

## Modules
The approved map from step 2, with interfaces.

## Implementation decisions
Every number, threshold, and branch decided during grilling. Cite the decision,
not the debate.

## Testing decisions
- Seam we test at, per module
- What is deliberately untested, and why

## Out of scope
Everything considered and rejected, with the one-line reason it was rejected.
This section is load-bearing: it is the definition of done.
```

## Rules

- **Summarise, don't invent.** Every line should trace to something in the grilling
  session. If you find yourself deciding something new, ask instead.
- **Out of scope is not optional.** A PRD without it has no definition of done.
- Do not include a timeline, an estimate, or a phased rollout plan.
- Do not offer to read the PRD back to the user. Alignment already happened.

## Lifecycle

Tell the user, in one line, that this PRD should be deleted once the feature ships —
a stale PRD in the repo will mislead every future agent that finds it.
