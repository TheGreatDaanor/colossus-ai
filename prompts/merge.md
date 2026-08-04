You are merging the output of a parallel agent run back into the base branch.

Several agents worked simultaneously in separate worktrees. Each produced a branch.
The branches are listed below, with the issue each one implemented. You are on the
base branch, and it is clean.

# Task

Merge each branch in the order given, one at a time. After each merge, get the tree
green before starting the next one.

## For each branch

1. `git merge --no-ff <branch>`
2. If there are conflicts, resolve them. Then run the full feedback loop from
   `CLAUDE.md`: test, typecheck, lint.
3. If the loop fails — even without a textual conflict — fix it before continuing.
   Independent branches that both pass in isolation routinely fail together.

## Conflicts you should expect, and how to resolve them

- **Migrations.** Two branches each added a migration with a colliding version or
  timestamp. Renumber the later one so both apply in sequence. Never merge two
  migrations into one file, and never drop one.
- **Shared registry files** — barrel exports, route tables, DI containers, i18n
  catalogues. Almost always a "keep both" resolution. Check for duplicate keys after.
- **Types.** Two branches widened the same type differently. Reconcile into one
  definition that satisfies both call sites; do not union your way out with `any`.
- **Lockfiles.** Regenerate from the merged manifest rather than hand-resolving.
- **Same-function edits.** Read both sides and both issues before choosing. If the
  two changes are genuinely incompatible, stop — see below.

## Rules

- **Never resolve a conflict by deleting a test.** If a test from one branch fails
  after merging another, that is a real integration bug and the most valuable thing
  this run will produce. Fix the code.
- **Never weaken a test** to get the merged tree green.
- Do not squash. Preserve each branch's commits.
- Do not push, tag, or open a PR.
- If two changes are genuinely incompatible and choosing between them is a product
  decision, **stop**. Abort that merge, leave the branch unmerged, and report it.
  Guessing here is worse than stopping.

# Output

    ## Merged
    <branch> — <issue> — clean | conflicts resolved in <files>

    ## Not merged
    <branch> — <why, and what decision a human needs to make>

    ## Feedback loop
    test / typecheck / lint — final results on the merged tree

    ## Integration bugs found
    <anything that only broke once branches were combined — this is the important part>

    ## Needs a human
    <resolutions you made that were judgement calls>
