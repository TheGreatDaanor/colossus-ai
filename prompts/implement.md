You are working through a backlog unattended. No human will answer questions during
this run, so do not ask any — make the most defensible choice and record it in the
commit message.

The full issue backlog is provided below in `<issues>`, and the recent commit history
in `<recent_commits>`. Read both before doing anything.

# 1. Pick exactly one task

Consider only issues with `status: open` **and** `type: afk`.

An issue is **eligible** only if every id in its `blocked-by` list belongs to an issue
with `status: done`. Skip anything still blocked.

If no eligible issue remains, output exactly this and stop, with no other text:

    NO MORE TASKS

Otherwise choose by priority:

1. Critical bug fixes — anything that leaves `main` broken
2. Development infrastructure — test harness, migrations, tooling the rest depends on
3. Tracer bullets — vertical slices that add visible functionality
4. Polish, quick wins, refactors

Within a tier, take the lowest id. State which issue you picked and why, in one line,
then work only on that issue. Do not batch two issues because they look related.

# 2. Explore before you write

Dispatch a sub-agent to survey the parts of the codebase this issue touches. Ask it
for the existing patterns, the module boundaries, and the test setup — not for file
contents. Keep your own context clean.

Read `CLAUDE.md` for the feedback-loop commands. If you need a convention decision,
pull the `coding-standards` skill.

# 3. Implement with TDD

Follow the `red-green-refactor` skill exactly. One failing test at a time. Confirm
red before you write the implementation.

Respect the module boundaries in the issue. If the issue names a module to create,
create that module with that interface — do not scatter the logic across new files.

**Never weaken a test to reach green.** If you are editing a test to make it pass,
stop, revert, and fix the implementation instead. If you genuinely believe the test
is wrong, leave it failing and explain in your summary.

# 4. Run the feedback loops

Run every command in the `Commands` section of `CLAUDE.md`: test, typecheck, lint.
Report each result explicitly. Fix anything you broke, then run them again.

Do not proceed to commit while any of them fails.

# 5. Commit

One commit per green cycle is ideal; several small commits are better than one large
one. The next iteration of this loop sees your commit messages as its only memory of
what just happened, so write them for that reader:

    <issue-id>: <what changed>

    <why, and any decision you made that a human might want to revisit>

# 6. Close the issue

Edit the issue file: set `status: done` in the frontmatter. Leave the file in place —
the loop needs it to resolve other issues' blockers.

# 7. Summarise

Finish with a short summary:

- Issue completed
- What changed, in two or three lines
- Feedback loop results
- **Decisions a human should check** — anything you guessed at
- **Anything you could not do**, and why

If you could not complete the issue, say so plainly, leave `status: open`, and do not
commit half-finished work. A clean stop is better than a green loop over broken code.
