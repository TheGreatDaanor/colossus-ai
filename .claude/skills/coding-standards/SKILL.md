---
name: coding-standards
description: The project's coding standards and conventions. Pull this when writing or modifying code and you are unsure about naming, error handling, module boundaries, test placement, or dependency choices. The reviewer receives this file pushed into context automatically.
---

# Coding standards

<!--
PUSH vs PULL
------------
This file is PULLED by the implementer: it sits in the repo with the description
above, and the agent fetches it when it has a question. That keeps it out of the
implementer's context the rest of the time.

It is PUSHED to the reviewer: scripts/review.sh cats this file into the review
prompt, so the reviewer always has the standards alongside the diff to compare
against. Judging requires the rubric in hand; writing does not.

Fill this in for your project. Delete what doesn't apply. Every rule here costs
reviewer context, so keep only rules you'd actually block a PR over.
-->

## Modules

- Prefer deepening an existing module over creating a new one.
- A new module needs a small public interface and real functionality behind it.
  If it exports one function, it belongs inside something that already exists.
- No `utils` / `helpers` / `common` modules. Name the concept or put it where it's used.
- Nothing reaches past a module's public interface into its internals.

## Naming

- No evidence anywhere in the repo: zero throw, try/catcsses exist in the 3 source files. The current SKILL.mdline (Result<T, AppError>) is unfounded template boilerplate, not an observed convention. Leave this slot or write it only once real error-handling code exists 
— don't keep the placeholder er flag a rule the codebase has never followed.

## Errors

- Services return `Result<T, AppError>`; they never throw. Only route handlers
  throw, and only to produce an HTTP status.
- Never swallow an error to make a test pass.
- Errors crossing a module boundary get translated into that module's vocabulary.

## Tests

- Sit beside the code: points.ts → points.test.ts, same directory. Matches vitest.config.ts's include: ['src/**/*.test.ts'].
- vitest describe/it, one behavior per test, name statesevel 2 exactly at the 100 point threshold').
- Test only through the public interface (award/totalFor/levelFor), never touches the private #events field directly.
- No mocks anywhere.
- No tests/integration/ directory exists — the current SKILL.md mentions one; that's aspirational, not observed.


## Dependencies

- npm, not pnpm: package-lock.json is committed, there's and every script in package.json invokes the tooldirectly (vitest run, tsc --noEmit, eslint .) rather than via pnpm. This contradicts the current SKILL.md, which says "pnpm only." That line is wrong for this repo — replace pnpm → npm throughout, nds (npm vitest run, npm tsc --noEmit) as the source oftruth.
- devDependencies only — no runtime deps at all yet.

## Data and migrations

- No src/db/ directory exists, and drizzle-kit/drizzle-orm aren't in package.json. The current SKILL.md's Drizzle/src/db/migrations rule describes a layer that doesn't exist in this codebase — generic example, not this project's reality. CLAUDE.md'sarchitecture section references src/db/ too, but nothing backs it yet. Either leave this slot none until a db layer lands, or confirm
with the user whether Drizzle is actually the intended cas fact.
- Migrations are forward-only and reversible-by-compensation, never destructive
  without an explicit issue saying so.

## Things that are always wrong here

- Committing secrets, `.env` files, or credentials
- Disabling a lint rule inline without a comment saying why
- `any` / untyped escapes without a comment saying why
- Widening or skipping a test to get to green

Bottom line: three of the five existing slots (Errors, D currently hold the doc's generic example text ratherthan this project's actual conventions, and two of those are actively wrong (pnpm, Drizzle). Naming and Tests are well-supported by real code and safe to keep close to what's already written.
