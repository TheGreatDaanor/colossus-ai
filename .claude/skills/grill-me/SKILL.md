---
name: grill-me
description: Relentlessly interview the user about a plan, brief, or feature idea until you and they share one design concept. Use at the START of any non-trivial piece of work, before any planning document exists. Trigger on "grill me", a pasted client brief or Slack message, a meeting transcript that needs turning into work, or any request to build a feature where the requirements have not been interrogated.
---

# Grill me

Interview me relentlessly about every aspect of this plan until we reach a shared
understanding. Walk down each branch of the design tree, resolving dependencies one
by one.

## Rules

- **One question at a time.** Never batch. I answer, you ask the next.
- **Always give your recommended answer** with the question, and a one-line reason.
  Most of the time I will take it; that is the point.
- **Do not produce a plan.** Not a summary, not a spec, not a bulleted design. If you
  feel the urge to write "Here's the plan:", ask another question instead.
- **Do not stop early.** Stopping is my call, not yours. Expect 20–80 questions.
- Number your questions so I can see the depth we're at.

## Before you start

Dispatch an exploration sub-agent to survey the codebase for anything relevant to
this brief: existing models, services, routes, naming conventions, test setup.
Report back only what changes the questions you'll ask. Do not paste file contents
into this context.

## What to grill on

Walk the design tree. Do not move to the next branch until the current one bottoms out.

1. **Scope boundary.** What is explicitly NOT in this? Push me to cut.
2. **Data model.** What new entities? What changes to existing ones? Nullable or not?
3. **Migration and backfill.** Existing rows — do they get retrofitted, ignored, or
   lazily computed? This is the question nobody thinks of and it always matters.
4. **Numbers.** Every threshold, rate, limit, curve, timeout. Never let a magic
   number pass unchallenged.
5. **Edge cases.** Concurrency, idempotency, replay, deletion, undo, partial failure.
6. **Surfaces.** Where does this appear in the UI? What does the empty state look like?
7. **Observability.** How will we know it works in production? How will we know it broke?
8. **Testing.** What is the seam we test at? What can't be tested and why is that OK?
9. **Modules.** Which existing modules change, and does this want a new deep module
   or does it belong inside one that exists?

## When I say stop

Do nothing else. Do not summarise. Do not offer to write a document. The conversation
itself is the asset — the next skill consumes it.

## If I'm impatient

If I say I'm in a hurry, switch to answering your own questions with your
recommendations and present them as a numbered list of decisions I can override.
Keep going through the full tree; just stop waiting on me.
