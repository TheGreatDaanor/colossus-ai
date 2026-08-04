#!/usr/bin/env bash
#
# One AFK iteration. Picks a single eligible issue, implements it, commits.
#
# Run this repeatedly BEFORE you ever run loop.sh. Read the log each time, fix
# prompts/implement.md where the agent went wrong, run it again. Tuning the prompt
# here is what makes an unattended loop safe.
#
# Usage: ./scripts/once.sh [--dry-run]

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

# Guard against a half-updated repo: an older lib/common.sh lacks helpers used
# below, and would fail with a cryptic "command not found" mid-run. Tests a
# variable, not a function, so it also works against a lib that predates both.
if (( ${KIT_LIB_VERSION:-0} < 2 )); then
  printf 'error: scripts/lib/common.sh is out of date (have v%s, need v2)\n' "${KIT_LIB_VERSION:-0}" >&2
  printf '       the kit updates as a SET. Copying one script across leaves the\n' >&2
  printf '       shared library behind. Re-install over the top:\n\n' >&2
  printf '           /path/to/ai-eng-workspace/install.sh "%s" --force\n\n' "$REPO_ROOT" >&2
  printf '       --force never touches CLAUDE.md, coding-standards, local.env or\n' >&2
  printf '       issues/. It backs up prompts/ and the Dockerfile before replacing\n' >&2
  printf '       them, so any tuning is recoverable from the .bak files.\n' >&2
  exit 1
fi


DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; export ALLOW_DIRTY; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_repo
init_logs

prompt="$(build_prompt "$PROMPTS_DIR/implement.md")"

if (( DRY_RUN )); then
  printf '%s\n' "$prompt"
  printf '\n--- eligible now ---\n' >&2
  eligible_issues afk | while IFS= read -r f; do printf '  %s\n' "$(basename "$f")" >&2; done
  exit 0
fi

require "$AGENT_BIN"

# The most confusing way this run can fail: the agent plans correctly, writes
# nothing, and reports that it could not run your tests. That is acceptEdits —
# file edits are auto-approved, Bash is not.
if [[ "$PERMISSION_MODE" == "acceptEdits" ]]; then
  warn "running on the host with --permission-mode acceptEdits"
  note "Bash commands will PROMPT for approval. If you walk away, the agent"
  note "cannot run npm/npx/your tests and will stop without writing code."
  note ""
  note "either stay and approve the prompts, or run it sandboxed, where Bash"
  note "is auto-approved because the blast radius is one repo:"
  note "    ./scripts/sandbox.sh ./scripts/once.sh"
  note ""
  note "to force it here anyway (approves everything on your real filesystem):"
  note "    PERMISSION_MODE=bypassPermissions ./scripts/once.sh"
  note ""
fi

n_eligible="$(eligible_issues afk | wc -l | tr -d ' ')"
if [[ "$n_eligible" == "0" ]]; then
  log "no eligible AFK issues — nothing to do"
  printf '%s\n' "$SENTINEL"
  exit 0
fi

log "$n_eligible eligible AFK issue(s)"

dirty="$(git -C "$REPO_ROOT" status --porcelain)"
if [[ -n "$dirty" ]]; then
  n="$(printf '%s\n' "$dirty" | wc -l | tr -d ' ')"
  warn "working tree is dirty ($n uncommitted file(s))"
  note "the agent runs 'git add -A' and commits when its tests pass. Your"
  note "uncommitted work gets swept into ITS commit, under ITS message — so"
  note "'what did the agent change?' becomes unanswerable, and reviewing or"
  note "reverting its work takes your changes with it."
  note ""
  note "commit or stash first:"
  note "    git add -A && git commit -m 'wip'"
  note "    git stash"
  note ""
  note "continuing in 5s — ctrl-c to stop.  --allow-dirty skips this pause."
  if [[ -z "${ALLOW_DIRTY:-}" ]]; then sleep 5; fi
fi

LOG_FILE="$LOG_DIR/once-$RUN_ID.log"
log "logging to $LOG_FILE"

set +e
printf '%s' "$prompt" | run_agent "$IMPLEMENT_MODEL" 2>&1 | tee "$LOG_FILE"
status=${PIPESTATUS[1]}
set -e

if (( status != 0 )); then
  die "agent exited $status — see $LOG_FILE"
fi

if grep -qF "$SENTINEL" "$LOG_FILE"; then
  log "agent reported: $SENTINEL"
fi

log "done"
