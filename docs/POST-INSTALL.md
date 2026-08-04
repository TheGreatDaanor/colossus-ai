# Post-install setup

`install.sh` copies files. It cannot know anything about your project, so it leaves
placeholders behind. This document shows you **every placeholder, where it lives, and
exactly what to replace it with.**

Every step below follows the same shape: the file to open, the text you'll find, the
text to replace it with, and a command to prove it worked.

## The whole job at a glance

| # | File you edit | What's in it now | Time | Auto-checked |
|---|---|---|---|---|
| 1 | `CLAUDE.md` | 7 × `TODO` (lines 19–35) | 10 min | yes |
| 2 | `.claude/skills/coding-standards/SKILL.md` | 5 × `TODO` (lines 33–56) | 15 min | yes |
| 3 | *(nothing to edit — just verify)* | — | 2 min | yes |
| 4 | `scripts/Dockerfile` | 1 commented-out block (~line 25) | 10 min | yes |
| 5 | *(nothing to edit — run a skill)* | — | 30 min | no |

**12 placeholders in total.**

**Find every placeholder at once:**

```bash
grep -rn "TODO" CLAUDE.md .claude/skills/coding-standards/SKILL.md scripts/Dockerfile
```

**Check your progress at any time:**

```bash
./scripts/doctor.sh
```

Exit 0 = ready. Exit 1 = blocking problems. Exit 2 = warnings only.

---

# Step 1 — `CLAUDE.md`

**File to edit:** `CLAUDE.md` (repo root)
**Placeholders to replace:** 7 — lines 19, 20, 21, 22, 24, 30, 35
**Why it matters:** these commands are the agent's *only* way of knowing whether the
code it just wrote works. Everything downstream — TDD, the AFK loop, the reviewer —
is built on them. Get them wrong and the whole thing operates on a fiction.

## What you'll find (lines 13–36)

```markdown
One sentence on what this project is.

## Commands

<!-- REQUIRED. These are the feedback loops. They must exit non-zero on failure. -->

- Test: `TODO`
- Typecheck: `TODO`
- Lint: `TODO`
- Dev server: `TODO`

Scoped test run (single module, for tight loops): `TODO`

## Architecture

<!-- Two or three lines. Where the deep modules are, not a file listing. -->

- TODO

## Rules

- Write the failing test first. See the `red-green-refactor` skill.
- Never edit files under `TODO` (generated).
- Prefer deepening an existing module over adding a shallow new one.
```

## What it should look like when you're done

A real example, for a TypeScript/Node repo:

```markdown
Course management platform for instructors and students. Next.js + Drizzle + SQLite.

## Commands

<!-- REQUIRED. These are the feedback loops. They must exit non-zero on failure. -->

- Test: `npx vitest run`
- Typecheck: `npx tsc --noEmit`
- Lint: `npx eslint .`
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
```

## Where to find each value

| Placeholder | What to put | Where to look it up |
|---|---|---|
| `One sentence on what this project is.` | One line: what it does, main stack | You know this one |
| `Test: ` | Command that runs your tests once | `package.json` scripts, `Makefile`, CI config |
| `Typecheck: ` | Type checker, no emit | Same. Skip if untyped language — write `none` |
| `Lint: ` | Linter, check-only mode | Same |
| `Dev server: ` | How to start it locally | `package.json` scripts, README |
| `Scoped test run` | Test one directory/module | Your runner's path-filter syntax |
| `Architecture` `- TODO` | 2–3 lines: where the deep modules are | Look at your top-level source dirs |
| `Never edit files under \`TODO\`` | Your generated/vendored dir | `migrations/`, `dist/`, `.next/`, `__generated__/` |

**Note:** the CI config is usually the best source. Whatever your CI runs is already
proven to be non-interactive and to exit correctly.

## Commands by stack

Copy the row that matches your project:

| Stack | Test | Typecheck | Lint |
|---|---|---|---|
| Node + Vitest | `npx vitest run` | `npx tsc --noEmit` | `npx eslint .` |
| Node + Jest | `npx jest --ci --watchAll=false` | `npx tsc --noEmit` | `npx eslint .` |
| pnpm | `pnpm test -- --run` | `pnpm typecheck` | `pnpm lint` |
| Python + pytest | `pytest -x -q` | `mypy .` | `ruff check .` |
| Python + uv | `uv run pytest -x -q` | `uv run mypy .` | `uv run ruff check .` |
| Go | `go test ./...` | `go vet ./...` | `golangci-lint run` |
| Rust | `cargo test` | `cargo check` | `cargo clippy -- -D warnings` |
| Java + Maven | `mvn -B test` | `mvn -B compile` | `mvn -B checkstyle:check` |
| .NET | `dotnet test` | `dotnet build` | `dotnet format --verify-no-changes` |

If a category doesn't apply, write `none` rather than leaving `TODO` — that tells
both the agent and `doctor.sh` it was a decision, not an oversight.

## Three rules your commands must obey

**1. Exit non-zero when something is broken.**

Watch for pipes. A shell pipeline returns the *last* command's status, so this
always succeeds no matter what the compiler says:

```markdown
- Typecheck: `tsc --noEmit | tee typecheck.log`     ← BROKEN, always exits 0
```

Same for anything ending `|| true`, `; true`, or `; echo done`. If your test command
can't report failure, the agent commits broken code and the loop reports success.
This is the most damaging thing you can get wrong here.

**2. Terminate.** Test runners default to **watch mode** when they detect a
terminal, and watch mode never exits. An unattended loop that hits one hangs until
the wall-clock cap, having accomplished nothing.

| Runner | Wrong — hangs | Right |
|---|---|---|
| Vitest | `vitest` | `vitest run` |
| Jest | `jest` | `jest --ci --watchAll=false` |
| Cargo watch | `cargo watch -x test` | `cargo test` |
| Anything | `--watch` anywhere | remove it |

**3. Never prompt.** No password, no "are you sure?", no interactive DB picker. The
agent can't answer, and it will hang exactly like watch mode.

## Troubleshooting

**`npm error code ENOENT` / exit 254**

npm found no `package.json` in the repo root. The command never ran — this is not a
failing test suite, and no amount of fixing your code will change it.

Either the repo isn't a Node project (use the row matching your actual stack from the
table above), or you're running from the wrong directory. Check:

```bash
ls package.json go.mod Cargo.toml pyproject.toml pom.xml 2>/dev/null
```

Whatever that finds tells you which row of the table you want.

**`npm error Missing script: "test"`**

`package.json` exists but has no script by that name. See what you actually have:

```bash
jq -r '.scripts | keys[]' package.json
```

Then either add the missing script, or skip the indirection and point `CLAUDE.md`
straight at the tool — `npx vitest run` rather than `npm test`. The direct form is
usually better here anyway: one less layer to swallow an exit code.

**Empty repo — no `package.json`, no `go.mod`, nothing?**

Then there is no project here yet. This kit drives an *existing* codebase; it needs
real commands to run. `doctor.sh` detects this and says so.

For a TypeScript project, scaffold one:

```bash
./scripts/bootstrap-node.sh
```

That writes `package.json` (with `test`/`typecheck`/`lint` scripts that run once and
exit non-zero on failure), strict `tsconfig.json`, flat-config ESLint, Vitest with
watch off, and one example deep module with a real test through its public
interface. Then it installs and verifies all three commands actually work.

For other stacks, scaffold however you normally would, then fill in the matching row
from the table above.

**Genuinely no tests, and you want to proceed anyway?**

Write `none` rather than leaving `TODO`, so it reads as a decision. But know the
cost: feedback-loop quality is the ceiling on agent output quality. With no tests
the agent cannot tell working code from broken, and the reviewer has nothing
mechanical to lean on. Make issue 001 dev-infrastructure instead — the
`prd-to-issues` skill explicitly permits that as a non-vertical slice.

## Verify

```bash
# terminates, and doesn't need a terminal?
timeout 300 npx vitest run < /dev/null; echo "exit=$?"
#   0   good
#   124 it hung — watch mode
#   127 command not found

# fails loudly? break something on purpose, then:
npx vitest run; echo "exit=$?"      # must NOT be 0
```

Or just let the checker do it — it runs all three commands with stdin closed under a
timeout, and flags pipes and watch mode statically:

```bash
./scripts/doctor.sh
```

---

# Step 2 — `.claude/skills/coding-standards/SKILL.md`

**File to edit:** `.claude/skills/coding-standards/SKILL.md`
**Placeholders to replace:** 5
**Why it matters:** `review.sh` pushes this entire file into the reviewer's context
alongside every diff. Judging needs a rubric in hand. Leave it as placeholders and
the reviewer falls back on its own generic priors — flagging things that are fine in
your codebase, missing things that aren't.

## The five placeholders

They're spread across the file. Each sits in a section that already has real rules
under it — you're filling a gap, not writing the section:

| Line | Section | Current text | Replace with |
|---|---|---|---|
| 33 | Naming | `- TODO: casing conventions per file type` | Your actual file/symbol casing |
| 38 | Errors | `- TODO: how errors are represented (exceptions / result types / error codes)` | How your code signals failure |
| 44 | Tests | `- TODO: test file location and naming` | Where tests live |
| 51 | Dependencies | `- TODO: package manager and lockfile policy` | Which package manager, lockfile rules |
| 56 | Data and migrations | `- TODO: migration tooling and naming` | Your migration tool and naming |

## Before and after, one at a time

**Naming (line 33)**

```markdown
- TODO: casing conventions per file type
```

becomes

```markdown
- Files `kebab-case.ts`. Components `PascalCase.tsx`. Types `PascalCase`,
  functions and variables `camelCase`, constants `SCREAMING_SNAKE`.
```

**Errors (line 38)**

```markdown
- TODO: how errors are represented (exceptions / result types / error codes)
```

becomes

```markdown
- Services return `Result<T, AppError>`; they never throw. Only route handlers
  throw, and only to produce an HTTP status.
```

**Tests (line 44)**

```markdown
- TODO: test file location and naming
```

becomes

```markdown
- Tests sit beside the code as `<module>.test.ts`. No `__tests__/` directories.
  Integration tests go in `tests/integration/`.
```

**Dependencies (line 51)**

```markdown
- TODO: package manager and lockfile policy
```

becomes

```markdown
- pnpm only. `pnpm-lock.yaml` is committed and must never be hand-edited.
  Never run `npm install` in this repo.
```

**Data and migrations (line 56)**

```markdown
- TODO: migration tooling and naming
```

becomes

```markdown
- Drizzle Kit. Generate with `pnpm db:generate`, never hand-write SQL in
  `src/db/migrations/`. Filenames are auto-numbered — do not renumber them.
```

## The fast way to write it

Don't compose this from memory. Derive it from the code you already have:

```bash
claude
```

then paste:

```
Read 15-20 representative source files across this repo. Infer the conventions
actually in use: file and symbol naming, how errors are represented and
propagated, where tests live and how they're named, which package manager and
lockfile, and how migrations are generated. Write each as one terse rule.
Where the codebase is inconsistent, say so and show both patterns rather than
picking one for me.
```

Then paste its answers into the five slots and delete the rest. The agent will
over-produce; your job here is deletion.

## What to delete

The template ships with sensible defaults under each heading. **Delete any that
aren't true for your project** — a rule your code doesn't follow is worse than no
rule, because the reviewer will flag every existing violation and bury the real
findings in noise.

Also delete anything your formatter or linter already enforces. Prettier, Black and
gofmt handle themselves; a rule about indentation is pure wasted reviewer context.

Target: **under 150 lines.** Keep only rules you'd block a pull request over.

## Verify

```bash
grep -c TODO .claude/skills/coding-standards/SKILL.md   # want: 0
wc -l   .claude/skills/coding-standards/SKILL.md        # want: under 150
```

---

# Step 3 — Statusline

**Nothing to edit.** `install.sh` already wired this up. You're just confirming it
works, because it fails silently.

**Why it matters:** the core rule is that model quality degrades as context fills,
and you clear at the boundary rather than compacting. You can't manage a budget you
can't see.

## What you should see

Restart Claude Code in the repo. At the bottom of the screen:

```
myrepo:main  Sonnet 4.5  42k (smart)
```

| Reading | Meaning | What to do |
|---|---|---|
| green, under 100k | smart zone | carry on |
| amber, 100–160k | degrading | finish the thought, then `/clear` |
| red, over 160k | dumb zone | `/clear` now — decisions made here are suspect |

**Clear, don't compact.** Clearing returns to an identical known state every time.
Compacting carries a lossy summary forward and the errors compound.

## If it shows nothing, or `0`

Work down this list:

1. **`jq` not installed** — by far the most common cause.
   - Debian/Ubuntu: `sudo apt install jq`
   - macOS: `brew install jq`
   - Windows: `winget install jqlang.jq`
2. **Not restarted.** Statusline config is read at startup.
3. **Windows: `bash` not on PATH.** The configured command is
   `bash .claude/statusline.sh`. Check with `bash --version`. Install Git Bash or WSL.
4. **Brand-new session.** There's no usage data until the first assistant reply.
   Send a message, then look again.
5. **Test it directly:**
   ```bash
   printf '{"model":{"display_name":"X"},"workspace":{"current_dir":"'"$PWD"'"},"transcript_path":""}' \
     | bash .claude/statusline.sh
   ```
   - Output with `0` → the script works; it just has no transcript yet. Fine.
   - No output at all → bash isn't resolving, or the file didn't install.

## Optional tuning

If you want to be warned earlier, set these in your shell profile:

```bash
export SMART_ZONE_LIMIT=80000     # amber earlier (default 100000)
export DUMB_ZONE_LIMIT=140000     # red earlier   (default 160000)
```

---

# Step 4 — `scripts/Dockerfile`

**File to edit:** `scripts/Dockerfile`
**What to fill:** one commented-out block, around line 25
**Why it matters:** the AFK loop runs with permissions pre-accepted — the agent edits
files without asking. That's only reasonable inside a container whose blast radius is
one bind-mounted repo.

But the image also has to be able to *run your tests*. If it can't, the container
starts fine and every feedback loop fails inside it — and the agent can't diagnose a
missing binary, so it assumes the code is wrong and starts "fixing" working code.
**A sandbox where your tests fail is worse than no sandbox.**

## What you'll find

```dockerfile
# ---- project toolchain: add anything your test/typecheck/lint commands need ----
# RUN corepack enable && corepack prepare pnpm@latest --activate
# RUN apt-get update && apt-get install -y postgresql-client
# -------------------------------------------------------------------------------
```

Both `RUN` lines are commented out — they're examples, not defaults.

## What to replace it with

Uncomment and adapt. For a pnpm + Postgres project:

```dockerfile
# ---- project toolchain: add anything your test/typecheck/lint commands need ----
RUN corepack enable && corepack prepare pnpm@latest --activate
RUN apt-get update && apt-get install -y --no-install-recommends \
      postgresql-client libpq-dev \
    && rm -rf /var/lib/apt/lists/*
# -------------------------------------------------------------------------------
```

## By stack

| Your project needs | Add this |
|---|---|
| pnpm | `RUN corepack enable && corepack prepare pnpm@latest --activate` |
| yarn | `RUN corepack enable && corepack prepare yarn@stable --activate` |
| Python | `RUN uv venv /opt/venv && . /opt/venv/bin/activate` (uv is already in the base image) |
| Poetry | `RUN pip install --break-system-packages poetry` |
| Postgres client | `RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client libpq-dev && rm -rf /var/lib/apt/lists/*` |
| MySQL client | `RUN apt-get update && apt-get install -y --no-install-recommends default-mysql-client && rm -rf /var/lib/apt/lists/*` |
| Playwright E2E | `RUN npx -y playwright@latest install --with-deps chromium` |
| Go | `RUN apt-get update && apt-get install -y --no-install-recommends golang-go && rm -rf /var/lib/apt/lists/*` |
| Rust | `RUN curl -sSf https://sh.rustup.rs \| sh -s -- -y` |
| Image processing | `RUN apt-get update && apt-get install -y --no-install-recommends imagemagick libvips-dev && rm -rf /var/lib/apt/lists/*` |

Rule of thumb: whatever your CI installs before running tests, install here.

**Databases are different.** Don't install a *server* in this image. Run it beside
the container and pass the host in. Keep the sandbox image about tools, not services.

## Build it, then prove it

```bash
./scripts/sandbox.sh --rebuild
```

First build takes several minutes. Then — and this is the part people skip — check
your feedback loop actually runs *in there*:

```bash
./scripts/sandbox.sh npx vitest run
./scripts/sandbox.sh npx tsc --noEmit
```

Or automatically:

```bash
./scripts/doctor.sh --sandbox
```

If those fail, fix the image before running a single loop.

## Troubleshooting the build

**`unable to find user agent: no matching entries in passwd file`**

The build succeeded but the container won't start. The base image already has a
user at your uid — `node:22` ships `node` at uid/gid **1000**, which is also the
first uid on most Linux desktops — so creating `agent` at 1000 collided and the
image ended up with a `USER` that doesn't exist.

Fixed in the current `scripts/Dockerfile`, which reuses whatever user already holds
that uid and sets `USER` numerically. If you installed before that fix, copy the
current Dockerfile over yours and rebuild:

```bash
./scripts/sandbox.sh --rebuild
```

`sandbox.sh` now runs `docker run --rm <image> true` straight after every build, so
this class of failure is caught at build time rather than mid-loop.

**Files created by the agent are owned by `root`**

The image was built without your uid baked in. Check and fix:

```bash
docker run --rm afk-sandbox:$(basename "$PWD") id -u   # should equal: id -u
./scripts/sandbox.sh --rebuild
```

**`permission denied` writing inside the container**

Something is writing outside `/repo` and `/home/agent`. Point the tool's cache at
`$HOME` — for example `npm config set cache /home/agent/.cache/npm`.

## Before your first unattended run

```bash
export ANTHROPIC_API_KEY=sk-...
```

`sandbox.sh` forwards a specific allow-list of variables into the container — never
your whole environment, never your home directory as a mount.

**Set a hard spend limit at your provider now.** A loop with a broken exit condition
will happily run all night.

---

# Step 5 — Architecture pass

**Nothing to edit.** You run a skill and act on what it finds.

**Why before your first feature, not after:** a codebase of *shallow* modules — many
small files, wide flat dependency graph, no natural test seams — hurts an agent
twice. It burns context just learning how things connect, and it offers nowhere
sensible to draw a test boundary, so the agent wraps individual functions and mocks
everything. Those tests stay green while the integration between them is broken.

Feedback-loop quality caps output quality, so shallow modules cap how well any agent
can ever do in your repo. Fixing that first pays back on every issue afterwards.
Doing it after you've shipped three features means redoing three features.

## Run it

```bash
claude
```

then:

```
use the improve-codebase-architecture skill
```

Takes a few minutes — it surveys the repo with sub-agents.

## What you get back

A ranked list. For each candidate: the files to merge, a proposed interface, the
evidence they're coupled, current test coverage, risk, and rough effort.

```
### 1. QuizScoringService

Files to merge:      src/quiz/score.ts, src/quiz/grade.ts, src/quiz/weights.ts
Proposed interface:  score(attempt): Result, explain(attempt): Breakdown
Why they're coupled: always imported together; co-change in 23 of last 30 commits
Current coverage:    zero tests
Testability gain:    one boundary around real scoring behaviour instead of three
                     function-level tests that mock each other
Risk:                weights.ts is imported by the reporting module
Effort:              medium
```

It proposes; it does not refactor. You choose.

## What to do with it

Take the top one or two, turn them into issues, and let the loop implement them:

```bash
claude
> /prd-to-issues
```

Look especially for the **big one**: a subsystem spanning front end to back end with
no end-to-end seam at all — an editor, a wizard, a checkout flow. Wrapping one so a
single test can drive it from the outer edge through to the data layer usually moves
an agent from hopeless to competent in that subsystem.

If it reports your codebase is already deep, believe it and move on. The skill is
instructed not to manufacture work.

---

# Done?

```bash
./scripts/doctor.sh
```

All green, then your first feature:

```bash
claude
> /grill-me @brief.md      # expect 20-80 questions — that IS the step
> /write-a-prd             # review the module map, skip the rest
> /prd-to-issues           # if slice 1 is horizontal, say "too horizontal" and retry

./scripts/once.sh          # run 3-4 times, tuning prompts/implement.md each time
./scripts/sandbox.sh ./scripts/loop.sh --max-iterations 10
./scripts/review.sh main..HEAD
```

Budget real time for tuning `prompts/implement.md` after watching `once.sh` a few
times. That prompt is what you'll iterate on most, and it's cheap to fix now and
expensive to discover at 3am via a loop that ran ten iterations wrong.
