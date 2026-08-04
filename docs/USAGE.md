# Using the kit — what each step does and what it wants from you

Setup is `docs/POST-INSTALL.md`. This is the run-book for actually doing work.

---

# First: clearing context

This is the single most-used operation in the workflow and the easiest to miss.

**To clear:** type `/clear` in Claude Code and press Enter. Everything resets to the
system prompt. The statusline drops back to a few thousand tokens.

```
/clear
```

**Do not use `/compact`.** It exists, and it looks like the helpful option. It
squeezes the conversation into a summary and continues. Two problems: the summary is
lossy in ways you can't see, and the resulting state is different every time.
Clearing returns to an identical known state on every single run, which is what makes
the workflow reproducible. Compacting accumulates sediment.

Other things that do *not* clear context: Ctrl+C (cancels the current turn), scrolling
back, `/undo`. Quitting and relaunching `claude` does clear — but `claude --continue`
and `claude -c` deliberately resume, so avoid those here.

## When to clear

Read the statusline. Colour is the instruction:

| Statusline | Meaning | Do |
|---|---|---|
| green, under 100k | smart zone | keep going |
| amber, 100–160k | degrading | finish the current step, then `/clear` |
| red, over 160k | dumb zone | `/clear` now — decisions made here are unreliable |

## Where the phase boundaries are

**This is what stops you hitting 200k.** Some steps must share context; others must
not. Getting this wrong is the most common way to blow the budget.

| Session | Steps | Why |
|---|---|---|
| 1 | `/grill-me` → `/write-a-prd` | **Must share context.** The PRD is a summary of the grilling; in a fresh session there's nothing to summarise. |
| — | `/clear` | ← the boundary people miss |
| 2 | `/prd-to-issues` | Reads the PRD **from disk**. Needs no memory of the grilling, and re-reading it costs 20–40k for nothing. |
| — | `/clear` | |
| 3 | QA, follow-up issues | Fresh eyes |

`once.sh`, `loop.sh` and `review.sh` each start their own process with a fresh
context every time. You never need to clear for those — that's the point of them.

**If grilling itself runs long** and you're heading for amber before the PRD exists,
don't clear (you'd lose the alignment). Instead say:

```
Wrap up. Give me your recommendations for everything still unresolved, then write the PRD.
```

---

# Second: git hygiene

The agent commits. That single fact drives three habits, and skipping them is how a
run becomes hard to unpick.

## Always start from a clean tree

**Why it matters:** every time the agent's tests pass, it runs `git add -A` and
commits. `add -A` stages *everything* — including whatever you were halfway through.
Your work ends up inside the agent's commit, under the agent's message.

The damage isn't the commit itself, it's what it costs you afterwards:

- `./scripts/review.sh` shows your changes mixed with the agent's, so you're
  reviewing your own code as if it were the agent's
- "what did the agent actually change?" has no answer any more
- reverting a bad agent commit takes your work with it
- during `loop.sh` this happens on *every* iteration, unattended

```bash
git status                              # should be empty
git add -A && git commit -m "wip"       # keep it
git stash                               # or set it aside
```

`once.sh` warns and pauses 5 seconds. `loop.sh` refuses to start — unattended, you
aren't there to judge. Override either with `--allow-dirty` if you really mean it.

## Always work on a branch

```bash
git checkout -b feat/points-and-streaks
```

The agent commits to whatever branch is checked out. On a branch you get:

- `./scripts/review.sh main..HEAD` means exactly "everything the agent did"
- a bad run is `git checkout main && git branch -D feat/...` away from gone
- `main` stays a known-good reference

On `main` directly, a bad run means picking commits apart by hand.

## Commit messages are the loop's memory

Each iteration starts with a fresh context and gets **the last five commit messages**
as its only record of what happened before. That's why `prompts/implement.md` asks
for the issue id and the reasoning. If you edit that prompt, keep that part — an
agent that writes "fix stuff" has told the next iteration nothing.

## Reading what happened

```bash
git log --oneline main..HEAD            # what the agent did
git log --stat -1                       # what the last commit touched
git diff main..HEAD -- src/             # the actual changes
```

If a commit looks wrong, `git revert <sha>` rather than resetting — the issue file
is already marked `done`, and reverting keeps the history honest about what was tried.

---

# The workflow, one step at a time

```
idea → /grill-me → /write-a-prd → [clear] → /prd-to-issues → [clear]
     → once.sh ×3-4 (tune) → loop.sh (AFK) → review.sh → manual QA
       └── human in the loop ──┘             └─ agent ─┘  └── you ──┘
```

---

## `/grill-me` — reach alignment

**Run it in:** a freshly cleared session, as the very first thing.

**What to give it:** whatever you have. A paragraph of intent, a pasted Slack
message, a client brief, a meeting transcript. Attach files with `@`:

```
/grill-me
I want to add gamification to the course platform — points and streaks,
because retention drops after the third lesson.
```

or

```
/grill-me @brief.md
```

**What happens:** it sends a sub-agent to survey your codebase (costs it tokens, not
yours — the sub-agent has its own context and returns only a summary). Then it starts
interviewing you. **One question at a time**, each with its own recommended answer.

**What's expected of you:** answer the questions. That's the whole job. You can:

- accept its recommendation — say "yes", "agreed", "go with that"
- override it — "no, do X instead"
- ask back — "what does the existing progress service do here?"
- defer — "out of scope"

**Expect 20 to 80 questions.** That is not a malfunction. It will ask about things you
hadn't considered — backfilling existing rows, what happens on concurrent writes,
what the empty state looks like. Those questions are the product. Answering them now
is far cheaper than discovering them in code review.

**How long:** 15–45 minutes. Roughly 15–40k of context.

**What good looks like:** questions get more specific as it goes, and at least two or
three make you stop and think.

**What bad looks like:** it stops after five questions and offers you a plan. Say
"keep going, you haven't covered testing or migrations yet."

**In a hurry:** `Give me a long list of all your remaining recommendations — I'll
override the ones I disagree with.` You lose some quality; you keep most of it.

**When you're done:** don't clear. Go straight to the next step.

---

## `/write-a-prd` — record the destination

**Run it in:** the *same* session as the grilling. It has no other source.

```
/write-a-prd
```

**What happens, in two parts.**

First it shows you a **module map** — the modules it intends to create or change,
with the public interface of each:

```
NEW      GamificationService   — points, levels, streak calculation
MODIFY   ProgressService       — emit completion events
MODIFY   dashboard route       — render points + level
```

Then it stops and waits.

**What's expected of you:** review *that list only*. This is the one thing worth
your attention in the whole step, because it decides whether your codebase ends up
with deep modules or a scatter of shallow ones. Ask yourself: is this three real
modules, or nine files each exporting one function? If it looks shallow, say so:

```
Too shallow. Merge the points/levels/streaks logic into one service with a small interface.
```

Approve, and it writes `issues/PRD-<slug>.md`.

**Do not read the PRD.** Alignment already happened during the grilling, and LLMs
summarise reliably. Reading it costs you 10 minutes and tests nothing. If that feels
uncomfortable, skim the **Out of scope** section only — that's the one part where a
misunderstanding would actually hurt.

**How long:** 2–5 minutes.

**Then:** `/clear`. The grilling has served its purpose; it's on disk now.

---

## `/prd-to-issues` — build the board

**Run it in:** a **freshly cleared** session. It reads the PRD from disk.

```
/prd-to-issues
```

**What happens:** it splits the PRD into independently grabbable issues in `issues/`,
each with `blocked-by` relationships, and tags each `afk` (an unattended agent can
finish it) or `human` (needs your eyes).

**What's expected of you: check that slice one is vertical.** This is the one
judgement call, and the agent gets it wrong by default.

It will want to slice **horizontally** — all the schema in issue 1, all the services
in issue 2, all the UI in issue 3. That feels tidy and is a trap: nothing is testable
until issue 3 lands, so the agent codes blind through the entire middle.

You want **vertical** slices — each issue cuts through schema *and* service *and* a
visible surface, so every issue ends in something you can look at.

The test: *what can I see or do when this issue is done that I couldn't before?* If
the answer is "nothing yet, it's groundwork", reject it:

```
The first slice is too horizontal. Slice 1 should include the schema change,
the new service, AND a minimal dashboard display, so I can see it working.
```

It will re-cut. This usually takes one round.

**What you'll get at the end:** the wave structure, showing what can run in parallel:

```
wave 1 (parallel):  001, 002
wave 2 (parallel):  003, 004   [after 001]
wave 3:             005        [after all]
```

If wave 1 has only one issue, the dependency graph is a chain — ask it to drop the
edges that aren't real.

**How long:** 5–15 minutes, mostly waiting.

**Then:** `/clear`, and leave Claude Code. The rest runs from your shell.

---

## `./scripts/once.sh` — one iteration, watched

**This is the step people skip, and skipping it is expensive.**

```bash
./scripts/once.sh
```

**What it does:** picks exactly one eligible AFK issue, implements it with TDD, runs
your test/typecheck/lint, commits, marks the issue done, and prints a summary. Then
stops. One issue, one run.

**What's expected of you: read the log.** That's why this exists. `prompts/implement.md`
is written generically and will not match your project on the first pass. You're
looking for:

- did it pick a sensible issue?
- did it write the failing test **first**, or bolt tests on afterwards?
- did it respect the module boundaries from the PRD?
- did it weaken a test to get to green?
- did it touch files it had no business touching?

Each time you find something, edit `prompts/implement.md` to prevent it, then run
again. **Three or four rounds is normal.** Every fix here is one you don't discover
at 3am across ten unattended iterations.

**Run it sandboxed.** This matters more than it looks:

```bash
./scripts/sandbox.sh ./scripts/once.sh
```

On the host, the agent runs with `acceptEdits`, which auto-approves **file edits
only** — every Bash command still prompts. So an unattended agent can plan and write
files but cannot run `npm`, `npx`, or your tests, and will correctly stop rather than
guess. You'll see it report a blocker like *"requires human approval for any
invocation of npm/npx, and no human is available"*.

Inside the container it uses `bypassPermissions`, which approves Bash too. That's
only defensible there, because the blast radius is one bind-mounted repo.

Running on the host is fine if you're sitting there approving prompts — useful for
the first run or two, when you want to see every command before it executes.

**How long:** 5–20 minutes per run.

**Where the log is:** `.agent-logs/once-<timestamp>.log`, and on screen.

**Options:**

```bash
./scripts/once.sh --dry-run       # print the assembled prompt, run nothing
./scripts/once.sh --allow-dirty   # skip the dirty-tree pause
```

Use `--dry-run` when you want to see exactly what the agent will be told.

**If it warns that the tree is dirty:** commit or stash first. The agent commits
with `git add -A`, so your uncommitted work lands inside its commit. See "git
hygiene" above.

**Move on when:** two consecutive runs produce work you'd have accepted in review.

---

## `./scripts/sandbox.sh` — the container wrapper

```bash
./scripts/sandbox.sh                                   # interactive shell inside
./scripts/sandbox.sh npm test                          # run one command inside
./scripts/sandbox.sh ./scripts/loop.sh --max-iterations 5   # the real use
```

**What it does:** runs whatever you pass it inside the Docker image, with your repo
bind-mounted at `/repo` and nothing else visible. Your API key is forwarded; your
home directory is not.

**Why it matters:** the loop runs with permissions pre-accepted — the agent edits
files without asking. Inside the container the blast radius is one repo. Outside it,
it's your home directory.

**Use it for anything unattended.** `once.sh` while you're watching is fine on the
host; `loop.sh` is not.

```bash
./scripts/sandbox.sh --rebuild    # after editing scripts/Dockerfile
```

---

## `./scripts/loop.sh` — the unattended run

```bash
./scripts/sandbox.sh ./scripts/loop.sh --max-iterations 10 --max-minutes 90
```

**What it does:** runs `once.sh` repeatedly until one of four things happens:

1. the backlog of eligible AFK issues is empty
2. the agent reports the sentinel (`NO MORE TASKS`)
3. it hits `--max-iterations` (default 10)
4. it hits `--max-minutes` (default 120)

It also stops if an iteration produces **no commit** — that means the agent is
spinning, and continuing would just burn budget repeating itself.

**What the flags mean:**

- `--max-iterations 10` — at most 10 issues. Each iteration is a full fresh-context
  agent run.
- `--max-minutes 90` — wall clock. Belt and braces: sentinels fail, agents get stuck
  in retry cycles, and a loop without a ceiling will run all night.

Start smaller than you think — `--max-iterations 3` on your first real run.

**What's expected of you:** nothing while it runs. That's the point. Afterwards, read
the summary and review the commits.

**Where the logs are:** `.agent-logs/loop-<id>.log` for the whole run, plus
`.agent-logs/loop-<id>-iter-N.log` per iteration.

**When it finishes** it prints the commit range and the exact review command:

```
review with:  ./scripts/review.sh abc1234..def5678
```

**Before you start:** the tree must be clean — `loop.sh` refuses otherwise, because
across several unattended iterations your uncommitted work would be absorbed into
the agent's commits repeatedly. Be on a feature branch, not `main`. And set a spend
limit at your provider.

```bash
git checkout -b feat/whatever
git status                     # empty
```

---

## `./scripts/review.sh` — automated review, fresh context

```bash
./scripts/review.sh main..HEAD        # everything since main
./scripts/review.sh                   # uncommitted changes
./scripts/review.sh abc1234..def5678  # the range loop.sh printed
```

**What it does:** starts a **new** agent process with the stronger model, pushes your
`coding-standards` skill in alongside the diff, and asks for a review. Output goes to
screen and `.agent-logs/review-<timestamp>.md`.

**Why a separate process:** the implementation run ends deep in the dumb zone. A
reviewer spawned inside that session is dumber than the thing that wrote the code.
This starts clean.

**What it looks for, in priority order:** fake tests first (assertions on mocks,
tests with no assertion, snapshots regenerated rather than reasoned about) — that's
the highest-value check. Then correctness and edge cases, then data and security,
then architecture, then your standards.

**What you get:** findings grouped Blocking / Should fix / Nits, and a verdict.

**What's expected of you:** treat it as a first pass, not a gate. It reports; it
doesn't fix. You decide what to act on.

**If the diff is enormous** it'll warn you. Review in smaller ranges — a reviewer
that's itself in the dumb zone isn't reviewing.

---

## Manual QA — the step that can't be automated

Run the app. Click through what was built. Try to break it.

**This is where your taste enters the codebase.** Teams that automate every step —
ideation, review, QA — ship things that technically work and are somehow bad. The
automated reviewer catches mechanical problems; only you notice that the flow is
confusing or the empty state is wrong.

**QA generates new issues.** Anything you find goes back on the board as a new issue
file, and the next loop picks it up. You can do this while a loop is still running.

---

# Full cycle, copy-pasteable

```bash
# ---- session 1: alignment (Claude Code) ----
claude
> /clear
> /grill-me @brief.md
  ... answer 20-80 questions ...
> /write-a-prd
  ... approve the module map ...
> /clear

# ---- session 2: the board (same window, cleared) ----
> /prd-to-issues
  ... reject slice 1 if it's horizontal ...
> /clear
   (leave Claude Code)

# ---- shell: tune ----
./scripts/once.sh
#   read .agent-logs/once-*.log, edit prompts/implement.md, repeat 3-4x

# ---- shell: run ----
./scripts/sandbox.sh ./scripts/loop.sh --max-iterations 3 --max-minutes 45

# ---- shell: review ----
./scripts/review.sh main..HEAD

# ---- you: QA ----
npm run dev
#   click through it; new problems become new issues/ files
```

---

# Quick reference

| I want to | Do |
|---|---|
| reset context | `/clear` — never `/compact` |
| see my context usage | statusline, bottom of the screen |
| start a feature | `/grill-me` in a cleared session |
| stop the agent guessing | answer the grilling honestly; that's what it's for |
| check what the loop will be told | `./scripts/once.sh --dry-run` |
| run unattended safely | `./scripts/sandbox.sh ./scripts/loop.sh ...` |
| stop a running loop | Ctrl+C — it commits per green cycle, so work is kept |
| see what happened overnight | `.agent-logs/loop-*.log`, `git log --oneline` |
| review the night's work | `./scripts/review.sh <range from loop output>` |
| add work found during QA | a new file in `issues/` |
| check the repo is still healthy | `./scripts/doctor.sh` |
