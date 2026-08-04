#!/usr/bin/env bash
#
# Is this repo actually ready to run agents against?
#
# Checks the five post-install steps mechanically, because three of them fail
# silently and "I think I did that" is not a verification strategy.
#
# Usage:
#   ./scripts/doctor.sh              # full check, runs your feedback loops
#   ./scripts/doctor.sh --quick      # skip actually running commands
#   ./scripts/doctor.sh --sandbox    # also verify the loops run INSIDE docker
#
# Exit 0 = ready. Exit 1 = blocking problems. Exit 2 = warnings only.

set -uo pipefail
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"
cd "$REPO_ROOT"

QUICK=0; CHECK_SANDBOX=0; CMD_TIMEOUT="${CMD_TIMEOUT:-300}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --sandbox) CHECK_SANDBOX=1; shift ;;
    --timeout) CMD_TIMEOUT="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

FAIL=0; WARN=0
declare -A CMDS=()         # declared here: section 4 reads it too
declare -A CMD_BROKEN=()   # commands already proven unrunnable, don't execute them
declare -A HOST_OK=()      # commands that actually passed on the host
_c() { if [[ -t 1 ]]; then printf '\033[%sm' "$1"; fi; }
head2() { printf '\n'; _c '1'; printf '%s\n' "$*"; _c '0'; }
pass() { _c '32'; printf '  PASS  '; _c '0'; printf '%s\n' "$*"; }
fail() { _c '31'; printf '  FAIL  '; _c '0'; printf '%s\n' "$*"; FAIL=$(( FAIL + 1 )); }
warn() { _c '33'; printf '  WARN  '; _c '0'; printf '%s\n' "$*"; WARN=$(( WARN + 1 )); }
note() { _c '2';  printf '        %s\n' "$*"; _c '0'; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '\n'; _c '1'; printf 'READINESS CHECK  %s\n' "$REPO_ROOT"; _c '0'

# ============================================================ 1. CLAUDE.md

head2 "1. CLAUDE.md commands"

if [[ ! -f CLAUDE.md ]]; then
  fail "CLAUDE.md not found — run the installer"
else
  words="$(wc -w < CLAUDE.md | tr -d ' ')"
  if (( words > 700 )); then
    warn "CLAUDE.md is ${words} words (~$(( words * 4 / 3 )) tokens)"
    note "this is pushed into EVERY session. Move conditional content into a skill."
  else
    pass "CLAUDE.md size ok (${words} words)"
  fi

  # Every remaining placeholder, with line numbers, so nothing is left behind
  # after the three commands are filled in. This is the step people half-finish.
  remaining="$(grep -n 'TODO' CLAUDE.md 2>/dev/null || true)"
  if [[ -n "$remaining" ]]; then
    n="$(printf '%s\n' "$remaining" | wc -l | tr -d ' ')"
    note "$n placeholder(s) still in CLAUDE.md:"
    printf '%s\n' "$remaining" | sed 's/^/          /'
    note "each one is listed with its replacement in docs/POST-INSTALL.md step 1"
  fi

  # `- Test: `cmd`` -> cmd
  get_cmd() {
    sed -n "s/^[[:space:]]*-[[:space:]]*$1:[[:space:]]*\`\(.*\)\`.*/\1/p" CLAUDE.md | head -1
  }

  for key in Test Typecheck Lint; do
    c="$(get_cmd "$key")"
    if [[ -z "$c" ]]; then
      fail "no '$key:' command found in CLAUDE.md"
      note "expected a line like:   - $key: \`npm test\`"
    elif [[ "$c" == *TODO* ]]; then
      fail "$key command is still TODO"
    else
      CMDS[$key]="$c"
      pass "$key: $c"
    fi
  done

  # Does the toolchain a command implies actually exist here? Catches the most
  # common post-install mistake: copying an example command out of the docs
  # without adapting it to the project.
  manifest_for() {
    case "$1" in
      npm\ *|npx\ *|node\ *|pnpm\ *|yarn\ *|bun\ *) printf 'package.json' ;;
      pytest*|python\ *|python3\ *|mypy\ *|ruff\ *|uv\ *|poetry\ *|tox*) \
        printf 'pyproject.toml setup.py setup.cfg tox.ini requirements.txt' ;;
      go\ *|golangci-lint*) printf 'go.mod' ;;
      cargo\ *) printf 'Cargo.toml' ;;
      mvn\ *) printf 'pom.xml' ;;
      gradle\ *|./gradlew*) printf 'build.gradle build.gradle.kts settings.gradle settings.gradle.kts' ;;
      dotnet\ *) printf '*.sln *.csproj *.fsproj' ;;
      make\ *) printf 'Makefile makefile GNUmakefile' ;;
      *) printf '' ;;
    esac
  }
  any_exists() {
    local pat
    for pat in $1; do
      # shellcheck disable=SC2086
      compgen -G "$pat" >/dev/null 2>&1 && return 0
    done
    return 1
  }
  for key in Test Typecheck Lint; do
    [[ -n "${CMDS[$key]:-}" ]] || continue
    want="$(manifest_for "${CMDS[$key]} ")"
    if [[ -n "$want" ]] && ! any_exists "$want"; then
      tool="${CMDS[$key]%% *}"
      fail "$key runs '$tool' but this repo has no ${want%% *}"
      note "looked for: $want"
      note "this command cannot run here. Did you copy the example from"
      note "docs/POST-INSTALL.md without adapting it to your project?"
      note "use the row matching YOUR stack in the 'Commands by stack' table"
      CMD_BROKEN[$key]=1   # don't run it below and report the same thing twice
    fi
  done

  # Distinguish "named the wrong toolchain" from "there is no toolchain here".
  # Different problems, different fixes.
  if (( ${#CMD_BROKEN[@]} > 0 )); then
    if ! any_exists 'package.json go.mod Cargo.toml pyproject.toml setup.py pom.xml build.gradle build.gradle.kts *.sln *.csproj Makefile'; then
      printf '\n'
      warn "no build manifest of any kind in this repo — it looks greenfield"
      note "this kit drives an existing codebase; it has nothing to run against yet."
      note "before your first feature, make issue 001 dev-infrastructure: scaffold"
      note "the project, wire up test/typecheck/lint, add one smoke test that fails"
      note "for the right reason. The prd-to-issues skill allows exactly this as a"
      note "legitimate non-vertical slice."
      note "then put the real commands in CLAUDE.md and re-run this check."
    fi
  fi

  # Non-blocking placeholders: useful, but the loop runs without them.
  for key in "Dev server"; do
    c="$(get_cmd "$key")"
    if [[ -z "$c" || "$c" == *TODO* ]]; then
      warn "'$key' still TODO in CLAUDE.md (not blocking, but the agent can't start your app)"
    fi
  done
  if grep -q 'Scoped test run.*TODO' CLAUDE.md 2>/dev/null; then
    warn "scoped test command still TODO — the agent will run the full suite every time"
    note "give it a path-filtered variant, e.g. \`npx vitest run src/services/points\`"
  fi
  if grep -q 'Never edit files under `TODO`' CLAUDE.md 2>/dev/null; then
    warn "generated-files path still TODO — the agent may edit generated code"
    note "e.g. src/db/migrations/, dist/, .next/, __generated__/"
  fi
  if grep -qE '^- TODO$' CLAUDE.md 2>/dev/null; then
    warn "Architecture section still TODO — 2-3 lines on where your deep modules are"
  fi

  # watch-mode detection is worth doing even in --quick mode: it is the most
  # common misconfiguration and it costs nothing to spot statically.
  for key in "${!CMDS[@]}"; do
    c="${CMDS[$key]}"
    case "$c" in
      *"vitest"*)
        [[ "$c" == *" run"* || "$c" == *--run* ]] || {
          fail "$key looks like vitest without 'run' — will hang in watch mode"
          note "use: vitest run"; }
        ;;
      *jest*)
        [[ "$c" == *watchAll=false* || "$c" == *--ci* || "$c" == *CI=* ]] || {
          warn "$key uses jest without --ci/--watchAll=false"
          note "if it enters watch mode the AFK loop will hang until the time cap"; }
        ;;
      *--watch*)
        fail "$key contains --watch — it will never terminate"
        ;;
    esac

    # `npm <binary>` is not a thing. npm only runs its own subcommands; to run a
    # locally-installed binary you need `npx`. pnpm and yarn DO fall through to
    # local binaries, so this check is npm-only.
    if [[ "$c" == npm\ * ]]; then
      sub="$(awk '{print $2}' <<<"$c")"
      case " run run-script test start stop restart ci install install-test i add \
uninstall remove rm update up outdated exec x init create publish pack version \
audit ls list link unlink prune rebuild dedupe config get set help doctor why \
view info fund ping pkg query search token whoami login logout access team org \
star unstar deprecate dist-tag hook owner profile root prefix bin explain diff \
sbom shrinkwrap " in
        *" $sub "*) ;;   # a real npm subcommand
        *)
          fail "$key: '$sub' is not an npm subcommand — npm cannot run it"
          note "npm only runs its own subcommands and package.json scripts."
          note "to run a local binary directly, use npx:"
          note "    - $key: \`npx $sub${c#npm $sub}\`"
          note "or add it as a script in package.json and use \`npm run $sub\`"
          CMD_BROKEN[$key]=1
          ;;
      esac
    fi

    # Exit-status laundering. A command that cannot report failure is the most
    # damaging misconfiguration available: the agent commits broken code and the
    # loop reports success. Static, so check it even in --quick mode.
    case "$c" in
      *"|"*)
        if [[ "$c" != *"||"* ]]; then
          fail "$key pipes its output — exit status will be the LAST command's, not the tool's"
          note "'$c' returns 0 even when it fails"
          note "drop the pipe, or wrap it in a script with 'set -o pipefail'"
        fi
        ;;
    esac
    case "$c" in
      *"|| true"*|*"; true"*|*"|| echo"*|*"; echo"*|*"|| :"*)
        fail "$key swallows failure — it can never report a broken build"
        ;;
    esac
  done

  if (( ! QUICK )) && (( ${#CMDS[@]} > 0 )); then
    note ""
    note "running your feedback loops (timeout ${CMD_TIMEOUT}s, stdin closed)..."
    for key in Test Typecheck Lint; do
      c="${CMDS[$key]:-}"; [[ -n "$c" ]] || continue
      if [[ -n "${CMD_BROKEN[$key]:-}" ]]; then
        note "$key: skipped — already established it cannot run here"
        continue
      fi
      start=$(date +%s)
      out="$(timeout "$CMD_TIMEOUT" bash -c "$c" </dev/null 2>&1)"
      rc=$?
      dur=$(( $(date +%s) - start ))

      if (( rc == 124 )); then
        fail "$key TIMED OUT after ${CMD_TIMEOUT}s — almost certainly watch mode"
        note "an AFK loop invoking this hangs until the wall-clock cap, doing nothing"
      elif (( rc == 127 )); then
        fail "$key: command not found"
        note "$(printf '%s' "$out" | tail -1)"
      elif grep -qiE 'ENOENT|Missing script|no such file or directory|could not (read|find|open) [^ ]*(package\.json|go\.mod|Cargo\.toml)|no pyproject|is not recognized|command not found|supported npm commands|Unknown command|unknown option' <<<"$out"; then
        # The distinction that matters: the tool never ran, versus it ran and
        # reported failures. Only the second one is "your tree is red today".
        fail "$key could not run at all (exit $rc) — this is not a failing test suite"
        note "$(printf '%s' "$out" | grep -iE 'ENOENT|Missing script|no such file' | head -1)"
        if grep -qi 'supported npm commands\|Unknown command' <<<"$out"; then
          sub="$(awk '{print $2}' <<<"${CMDS[$key]}")"
          note "npm has no '$sub' subcommand. Use: \`npx $sub ...\`"
        elif grep -qi 'Missing script' <<<"$out"; then
          script="$(grep -oiE 'Missing script: *"[^"]+"' <<<"$out" | head -1 | sed 's/.*"\(.*\)"/\1/')"
          note "package.json exists but has no \"${script:-?}\" script"
          note "either add it to the \"scripts\" block, or point CLAUDE.md straight"
          note "at the tool, e.g.  - $key: \`npx vitest run\`"
          note "current scripts: $(jq -r '.scripts // {} | keys | join(", ")' package.json 2>/dev/null || echo '?')"
        elif grep -qi 'ENOENT' <<<"$out"; then
          note "no package.json found in $(pwd) — this is not a Node project"
          note "use the row matching your stack in the 'Commands by stack' table"
          note "in docs/POST-INSTALL.md (pytest, go test, cargo test, ...)"
        fi
      elif (( rc != 0 )); then
        warn "$key ran and exited $rc (${dur}s)"
        note "expected if your tree is genuinely red right now; investigate otherwise"
        note "$(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
      else
        pass "$key exited 0 in ${dur}s"
        HOST_OK[$key]=1
        if [[ "$key" == "Test" ]] && (( dur > 60 )); then
          warn "test suite takes ${dur}s — the agent runs this dozens of times"
          note "add a scoped variant to CLAUDE.md for tight loops"
        fi
      fi
    done

  fi
fi

# ================================================== 2. coding standards

head2 "2. Coding standards"
STD=".claude/skills/coding-standards/SKILL.md"
if [[ ! -f "$STD" ]]; then
  fail "$STD not found"
else
  # NOT `|| echo 0`: grep -c already prints "0" and THEN exits 1, so the fallback
  # appends a second zero and the arithmetic below dies on "0\n0".
  todos="$(grep -c 'TODO' "$STD" 2>/dev/null)" || true
  todos="${todos:-0}"
  lines="$(wc -l < "$STD" | tr -d ' ')"
  if (( todos > 0 )); then
    fail "$todos TODO placeholder(s) left in coding-standards"
    note "the reviewer compares every diff against this file; empty means no rubric"
    note "bootstrap it: ask the agent to infer conventions from 15-20 real files"
  else
    pass "no TODOs left"
  fi
  if (( lines > 200 )); then
    warn "$lines lines — this is pushed into every review, trim to the rules you'd block a PR over"
  elif (( lines > 10 )); then
    pass "length ok ($lines lines)"
  fi
fi

# ========================================================= 3. statusline

head2 "3. Statusline token counter"
if ! have jq; then
  fail "jq not installed — the statusline cannot compute a token count"
  note "apt install jq | brew install jq | winget install jqlang.jq"
else
  pass "jq present"
fi

if [[ ! -f .claude/statusline.sh ]]; then
  fail ".claude/statusline.sh missing"
elif [[ ! -f .claude/settings.json ]]; then
  fail ".claude/settings.json missing — statusline not wired up"
else
  if have jq && jq -e '.statusLine.command' .claude/settings.json >/dev/null 2>&1; then
    pass "statusLine configured in settings.json"
  else
    fail "settings.json has no statusLine entry"
  fi

  # synthetic transcript: proves the parser works end to end
  tf="$(mktemp)"; sf="$(mktemp)"
  printf '%s\n' '{"message":{"usage":{"input_tokens":40000,"cache_read_input_tokens":1500,"output_tokens":500}}}' > "$tf"
  printf '{"model":{"display_name":"Test"},"workspace":{"current_dir":"%s"},"transcript_path":"%s"}' "$REPO_ROOT" "$tf" > "$sf"
  out="$(bash .claude/statusline.sh < "$sf" 2>/dev/null)"
  rm -f "$tf" "$sf"

  if [[ -z "$out" ]]; then
    fail "statusline produced no output"
    note "check bash is on PATH (Git Bash / WSL on Windows)"
  elif grep -qE '4[0-9]k' <<<"$out"; then
    pass "token counter works: $(sed 's/\x1b\[[0-9;]*m//g' <<<"$out")"
  else
    warn "statusline ran but no token count: $(sed 's/\x1b\[[0-9;]*m//g' <<<"$out")"
    note "reads 0 in a fresh session until the first assistant turn — that is normal"
  fi
fi

# ============================================================ 4. sandbox

head2 "4. Sandbox"
if [[ ! -f scripts/Dockerfile ]]; then
  fail "scripts/Dockerfile missing"
elif ! have docker; then
  warn "docker not installed — you will be running unattended loops unsandboxed"
  note "the loop edits files with permissions pre-accepted; outside a container"
  note "the blast radius is your home directory, not one repo"
else
  pass "docker present"
  if grep -qE '^\s*(RUN|COPY)' <<<"$(sed -n '/---- project toolchain/,/^# ----/p' scripts/Dockerfile)"; then
    pass "project toolchain block has been filled in"
  else
    warn "project toolchain block in scripts/Dockerfile is still empty"
    note "if your tests need anything beyond node, they will fail inside the sandbox"
    note "a sandbox where the feedback loop fails is worse than no sandbox"
  fi

  img="afk-sandbox:$(basename "$REPO_ROOT")"
  if docker image inspect "$img" >/dev/null 2>&1; then
    pass "image built: $img"

    # The image name is derived from the directory name, so a rebuilt or
    # recreated repo inherits whatever image was there before — possibly built
    # from a different Dockerfile. Compare timestamps rather than assume.
    img_epoch="$(docker image inspect -f '{{.Created}}' "$img" 2>/dev/null | head -1)"
    img_epoch="$(date -d "$img_epoch" +%s 2>/dev/null || echo 0)"
    df_epoch="$(stat -c %Y scripts/Dockerfile 2>/dev/null || stat -f %m scripts/Dockerfile 2>/dev/null || echo 0)"
    if (( img_epoch > 0 && df_epoch > img_epoch )); then
      fail "image is OLDER than scripts/Dockerfile — it is stale"
      note "built:      $(date -d "@$img_epoch" 2>/dev/null || echo '?')"
      note "Dockerfile: $(date -d "@$df_epoch" 2>/dev/null || echo '?')"
      note "the image name comes from the directory name, so a recreated repo"
      note "silently reuses an old image. Rebuild:"
      note "    ./scripts/sandbox.sh --rebuild"
    fi

    # Building and starting are different things. A USER that doesn't resolve
    # passes the build and fails at run time.
    if err="$(docker run --rm "$img" true 2>&1)"; then
      pass "container starts"
      whoami_out="$(docker run --rm "$img" id -u 2>/dev/null || echo '?')"
      if [[ "$whoami_out" == "$(id -u)" ]]; then
        pass "container uid matches yours ($whoami_out) — bind-mounted files stay yours"
      else
        warn "container uid $whoami_out != host uid $(id -u) — files may end up root-owned"
        note "rebuild so the uid is baked in: ./scripts/sandbox.sh --rebuild"
      fi
    else
      fail "image exists but the container will not start"
      note "$(printf '%s' "$err" | head -1)"
      case "$err" in
        *"unable to find user"*|*"no matching entries in passwd"*)
          note "the USER in scripts/Dockerfile does not exist in the image — your host"
          note "uid likely collides with one in the base image. Update the Dockerfile"
          note "to resolve the user numerically, then: ./scripts/sandbox.sh --rebuild"
          ;;
      esac
    fi
    if (( CHECK_SANDBOX )) && [[ -n "${CMDS[Test]:-}" ]]; then
      if [[ -z "${HOST_OK[Test]:-}" ]]; then
        # Running it in the container would fail for the same reason and produce
        # a misleading "toolchain missing" verdict. Fix the host first.
        note "skipping in-container run — the test command does not pass on the host yet"
        note "fix section 1, then re-run with --sandbox"
      else
        note "running your test command inside the container..."
        if err="$(timeout "$CMD_TIMEOUT" ./scripts/sandbox.sh bash -lc "${CMDS[Test]}" 2>&1)"; then
          pass "test command works INSIDE the sandbox"
        else
          fail "test command passes on the host but FAILS inside the sandbox"
          note "$(printf '%s' "$err" | grep -viE '^\[|^warn:' | tail -2 | tr '\n' ' ')"
          note "the image is missing something your tests need — add it to the"
          note "toolchain block in scripts/Dockerfile, then: ./scripts/sandbox.sh --rebuild"
        fi
      fi
    elif (( ! CHECK_SANDBOX )); then
      note "re-run with --sandbox to verify your loops work inside the container"
    fi
  else
    warn "image not built yet — run ./scripts/sandbox.sh --rebuild"
  fi
fi

if [[ -z "${ANTHROPIC_API_KEY:-}${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  warn "no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN exported"
  note "the agent cannot authenticate inside the sandbox without it"
fi

# ======================================================= 5. architecture

head2 "5. Architecture pass"
if [[ -f .claude/skills/improve-codebase-architecture/SKILL.md ]]; then
  pass "skill installed"
  note "not machine-checkable — but run it before your first feature:"
  note "    claude"
  note "    > use the improve-codebase-architecture skill"
  note "shallow modules cap how well ANY agent can do here. Fixing that after"
  note "shipping three features means redoing three features."
else
  fail "improve-codebase-architecture skill missing"
fi

# =============================================================== extras

head2 "Workflow plumbing"
for f in prompts/implement.md prompts/review.md scripts/once.sh scripts/loop.sh issues/_TEMPLATE.md; do
  [[ -f "$f" ]] && pass "$f" || fail "$f missing"
done

if git rev-parse --git-dir >/dev/null 2>&1; then
  pass "git repository"
  # check-ignore needs a path the pattern can actually match; ".agent-logs/" is a
  # directory pattern and the directory may not exist yet on a fresh install.
  if git check-ignore -q .agent-logs/probe.log 2>/dev/null; then
    pass ".agent-logs ignored"
  else
    warn ".agent-logs not gitignored — agent transcripts will be committed"
  fi
else
  fail "not a git repository — the loop scripts need one"
fi

# =============================================================== summary

printf '\n'
_c '1'; printf 'SUMMARY\n'; _c '0'
if (( FAIL > 0 )); then
  _c '31'; printf '  %d blocking problem(s), %d warning(s)\n' "$FAIL" "$WARN"; _c '0'
  note "see docs/POST-INSTALL.md"
  printf '\n'; exit 1
elif (( WARN > 0 )); then
  _c '33'; printf '  ready, with %d warning(s)\n' "$WARN"; _c '0'
  note "you can run the loop, but read the warnings first"
  printf '\n'; exit 2
else
  _c '32'; printf '  ready\n'; _c '0'
  note "next:  claude  ->  /grill-me  ->  /write-a-prd  ->  /prd-to-issues"
  note "then:  ./scripts/once.sh   (run it a few times and tune prompts/implement.md)"
  printf '\n'; exit 0
fi
