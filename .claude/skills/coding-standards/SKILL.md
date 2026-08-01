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

- Files `kebab-case.ts`. Components `PascalCase.tsx`. Types `PascalCase`,
  functions and variables `camelCase`, constants `SCREAMING_SNAKE`.
- use lowercase.
- Names state behaviour, not implementation. No `data`, `info`, `manager`, `handler`.

## Errors

- Services return `Result<T, AppError>`; they never throw. Only route handlers
  throw, and only to produce an HTTP status.
- Never swallow an error to make a test pass.
- Errors crossing a module boundary get translated into that module's vocabulary.

## Tests

- Tests sit beside the code as `<module>.test.ts`. No `__tests__/` directories.
  Integration tests go in `tests/integration/`.
- Test through the module's public interface, against real in-memory dependencies.
- No assertions on mocks.
- One behaviour per test; the name states the behaviour.

## Dependencies

- pnpm only. `pnpm-lock.yaml` is committed and must never be hand-edited.
  Never run `npm install` in this repo.
- New third-party dependencies need explicit approval — flag, don't add.

## Data and migrations

- Drizzle Kit. Generate with `pnpm db:generate`, never hand-write SQL in
  `src/db/migrations/`. Filenames are auto-numbered — do not renumber them.
- Migrations are forward-only and reversible-by-compensation, never destructive
  without an explicit issue saying so.

## Things that are always wrong here

- Committing secrets, `.env` files, or credentials
- Disabling a lint rule inline without a comment saying why
- `any` / untyped escapes without a comment saying why
- Widening or skipping a test to get to green
