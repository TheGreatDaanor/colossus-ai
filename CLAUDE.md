# Project

<!--
KEEP THIS FILE UNDER ~500 TOKENS.

It is pushed into the system prompt of every single session. Every token here is a
token of smart zone you have already spent before typing anything.

Only put things here that are true for EVERY task. Anything conditional belongs in
a skill under .claude/skills/, which the agent pulls on demand.
-->

One sentence on what this project is.

## Commands

<!-- REQUIRED. These are the feedback loops. They must exit non-zero on failure. -->

- Test: `npx vitest run`
- Typecheck: `npx tsc --noEmit`
- Lint: `npx eslint`
- Dev server: `npm run dev`

Scoped test run (single module, for tight loops): `npx vitest run src/services/points`

## Architecture

<!-- Two or three lines. Where the deep modules are, not a file listing. -->

- Business logic lives in `src/services/*` — one deep module per domain
  (courses, quizzes, progress). Routes are thin and call into services.
- Database access goes through `src/db/` only. Nothing else imports Drizzle.

## Rules

- Write the failing test first. See the `red-green-refactor` skill.
- Never edit files under `src/db/migrations/` (generated).
- Prefer deepening an existing module over adding a shallow new one.
