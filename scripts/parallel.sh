#!/usr/bin/env bash
#
# One parallel wave: plan -> worktree per issue -> implement concurrently -> merge.
#
# Each agent gets its own git worktree on its own branch, so they never contend for
# the working directory. The planner decides which issues can run together; the
# merger reconciles the branches afterwards and fixes what only breaks once the
# branches are combined.
#
# Run loop.sh successfully a few times before reaching for this.
#
# Usage: ./scripts/parallel.sh [--max-parallel N] [--no-merge] [--dry-run]

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

MAX_PARALLEL="${MAX_PARALLEL:-4}"
DO_MERGE=1
DRY_RUN=0
WORKTREE_ROOT="${WORKTREE_ROOT:-$REPO_ROOT/../.afk-worktrees}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-parallel) MAX_PARALLEL="${2:?}"; shift 2 ;;
    --no-merge)     DO_MERGE=0; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_repo
require "$AGENT_BIN"
require jq
init_logs

[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] \
  || die "working tree must be clean before a parallel run"

BASE_BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
BASE_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
log "base: $BASE_BRANCH @ ${BASE_COMMIT:0:8}"

# ------------------------------------------------------------------ 1. plan

log "planning wave..."
plan_raw="$(build_prompt "$PROMPTS_DIR/plan.md" | run_agent "$REVIEW_MODEL")"

# Tolerate a fenced block even though the prompt forbids it.
plan_json="$(printf '%s' "$plan_raw" | sed -n '/\[/,/\]/p' | sed 's/^```.*$//')"

if ! printf '%s' "$plan_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
  printf '%s\n' "$plan_raw" >&2
  die "planner did not return a JSON array"
fi

count="$(printf '%s' "$plan_json" | jq 'length')"
if [[ "$count" == "0" ]]; then
  log "planner found no parallelisable work"
  exit 0
fi

(( count > MAX_PARALLEL )) && {
  log "trimming wave from $count to $MAX_PARALLEL"
  plan_json="$(printf '%s' "$plan_json" | jq --argjson n "$MAX_PARALLEL" '.[:$n]')"
  count="$MAX_PARALLEL"
}

log "wave of $count:"
printf '%s' "$plan_json" | jq -r '.[] | "  \(.id)  \(.slug)  -> \(.branch)"' >&2

if (( DRY_RUN )); then exit 0; fi

# ------------------------------------------------------------- 2. worktrees + run

mkdir -p "$WORKTREE_ROOT"
declare -a BRANCHES=() PIDS=() IDS=()

cleanup() {
  log "cleaning up worktrees"
  local wt
  for wt in "${WORKTREES[@]:-}"; do
    [[ -n "$wt" ]] && git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null || true
  done
  git -C "$REPO_ROOT" worktree prune 2>/dev/null || true
}
declare -a WORKTREES=()
trap cleanup EXIT

while IFS=$'\t' read -r id slug branch; do
  [[ -n "$id" ]] || continue
  wt="$WORKTREE_ROOT/$id-$slug"

  git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$REPO_ROOT" branch -D "$branch" 2>/dev/null || true
  git -C "$REPO_ROOT" worktree add -b "$branch" "$wt" "$BASE_COMMIT" >/dev/null

  WORKTREES+=("$wt")
  BRANCHES+=("$branch")
  IDS+=("$id")

  iter_log="$LOG_DIR/parallel-$RUN_ID-$id.log"
  log "launching $id in $wt"

  (
    cd "$wt"
    REPO_ROOT="$wt"
    ISSUES_DIR="$wt/issues"
    PROMPTS_DIR="$wt/prompts"
    {
      printf 'FOCUS: work ONLY on issue %s. Ignore every other issue in the backlog below.\n\n' "$id"
      build_prompt "$wt/prompts/implement.md"
    } | run_agent "$IMPLEMENT_MODEL"
  ) >"$iter_log" 2>&1 &

  PIDS+=("$!")
done < <(printf '%s' "$plan_json" | jq -r '.[] | [.id, .slug, .branch] | @tsv')

log "waiting on ${#PIDS[@]} agent(s)..."
failed=0
for i in "${!PIDS[@]}"; do
  if wait "${PIDS[$i]}"; then
    log "issue ${IDS[$i]} finished"
  else
    warn "issue ${IDS[$i]} FAILED — see $LOG_DIR/parallel-$RUN_ID-${IDS[$i]}.log"
    failed=$(( failed + 1 ))
  fi
done

# --------------------------------------------------------------- 3. keep branches

# Branches live in the main repo once the worktree is removed, so the merge step
# (and you, if it goes wrong) can still reach them.
declare -a MERGEABLE=()
for i in "${!BRANCHES[@]}"; do
  b="${BRANCHES[$i]}"
  if [[ "$(git -C "$REPO_ROOT" rev-parse "$b")" != "$BASE_COMMIT" ]]; then
    MERGEABLE+=("$b")
  else
    warn "branch $b has no commits — dropping"
  fi
done

if (( ${#MERGEABLE[@]} == 0 )); then
  die "no branch produced commits"
fi

if (( DO_MERGE == 0 )); then
  log "branches ready (not merging):"
  printf '  %s\n' "${MERGEABLE[@]}" >&2
  exit 0
fi

# ------------------------------------------------------------------- 4. merge

cleanup; trap - EXIT

log "merging ${#MERGEABLE[@]} branch(es) with $REVIEW_MODEL"

branch_block=""
for b in "${MERGEABLE[@]}"; do
  branch_block+="$b — $(git -C "$REPO_ROOT" log --format='%s' -1 "$b")"$'\n'
done

merge_log="$LOG_DIR/parallel-$RUN_ID-merge.log"
prompt="$(cat "$PROMPTS_DIR/merge.md")

Base branch: $BASE_BRANCH

<branches>
$branch_block
</branches>"

set +e
printf '%s' "$prompt" | run_agent "$REVIEW_MODEL" 2>&1 | tee "$merge_log"
status=${PIPESTATUS[1]}
set -e

(( status == 0 )) || warn "merger exited $status — see $merge_log"

log "wave complete. failed agents: $failed"
log "review with:  ./scripts/review.sh $BASE_COMMIT..HEAD"
