#!/usr/bin/env bash
# Shared helpers for the AFK scripts. Source this; do not execute it.
# shellcheck shell=bash

set -euo pipefail

# ---------------------------------------------------------------- paths + config

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$(cd "$LIB_DIR/.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPTS_DIR/.." && pwd)}"

ISSUES_DIR="${ISSUES_DIR:-$REPO_ROOT/issues}"
PROMPTS_DIR="${PROMPTS_DIR:-$REPO_ROOT/prompts}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/.agent-logs}"
STANDARDS_FILE="${STANDARDS_FILE:-$REPO_ROOT/.claude/skills/coding-standards/SKILL.md}"

AGENT_BIN="${AGENT_BIN:-claude}"
IMPLEMENT_MODEL="${IMPLEMENT_MODEL:-sonnet}"
REVIEW_MODEL="${REVIEW_MODEL:-opus}"
PERMISSION_MODE="${PERMISSION_MODE:-acceptEdits}"

SENTINEL="${SENTINEL:-NO MORE TASKS}"
COMMIT_CONTEXT="${COMMIT_CONTEXT:-5}"

# ---------------------------------------------------------------------- output

_c() { if [[ -t 2 ]]; then printf '\033[%sm' "$1" >&2; fi; }
log()  { _c '2;37'; printf '[%s] ' "$(date +%H:%M:%S)"; _c '0'; printf '%s\n' "$*" >&2; }
warn() { _c '33';   printf 'warn: %s\n' "$*" >&2; _c '0'; }
die()  { _c '31';   printf 'error: %s\n' "$*" >&2; _c '0'; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_repo() {
  require git
  git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 \
    || die "not a git repository: $REPO_ROOT"
}

# ------------------------------------------------------------------ issue files

# Every issue markdown file, sorted. Skips README.md and anything starting with _
# (templates) or PRD- (destination documents, not tasks).
issue_files() {
  [[ -d "$ISSUES_DIR" ]] || return 0
  find "$ISSUES_DIR" -maxdepth 1 -type f -name '*.md' \
    ! -name 'README.md' ! -name '_*' ! -name 'PRD-*' \
    | LC_ALL=C sort
}

# issue_field <file> <key> — read one frontmatter field, trimmed.
issue_field() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 0
  awk -v key="$key" '
    NR == 1 && $0 ~ /^---[[:space:]]*$/ { fm = 1; next }
    fm && $0 ~ /^---[[:space:]]*$/      { exit }
    fm {
      if (index($0, key ":") == 1) {
        v = substr($0, length(key) + 2)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
        print v
        exit
      }
    }
  ' "$file"
}

# blockers <file> — whitespace-separated blocker ids from `blocked-by: [001, 002]`
blockers() {
  issue_field "$1" 'blocked-by' | tr -d '[]",' | tr -s '[:space:]' ' '
}

# status_of_id <id> — status of the issue with that id, or empty if unknown.
status_of_id() {
  local want="$1" f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    if [[ "$(issue_field "$f" id)" == "$want" ]]; then
      issue_field "$f" status
      return 0
    fi
  done < <(issue_files)
  return 0
}

# eligible_issues [type] — open issues of <type> whose blockers are all done.
# type defaults to "afk"; pass "any" to ignore the type field.
eligible_issues() {
  local want_type="${1:-afk}"
  local f st ty b bst ok
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    st="$(issue_field "$f" status)"
    [[ "$st" == "open" ]] || continue
    ty="$(issue_field "$f" type)"
    [[ "$want_type" == "any" || "$ty" == "$want_type" ]] || continue
    ok=1
    for b in $(blockers "$f"); do
      bst="$(status_of_id "$b")"
      if [[ -z "$bst" ]]; then
        warn "$(basename "$f"): blocked-by references unknown id '$b'"
        ok=0; break
      fi
      [[ "$bst" == "done" ]] || { ok=0; break; }
    done
    (( ok )) && printf '%s\n' "$f"
  done < <(issue_files)
  return 0
}

# ------------------------------------------------------------------ prompt build

all_issues_block() {
  local f any=0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    any=1
    printf '===== %s =====\n' "$(basename "$f")"
    cat "$f"
    printf '\n'
  done < <(issue_files)
  (( any )) || printf '(no issue files found in %s)\n' "$ISSUES_DIR"
}

recent_commits_block() {
  git -C "$REPO_ROOT" log -"$COMMIT_CONTEXT" --format='--- %h %s%n%b' --stat 2>/dev/null \
    || printf '(no commit history)\n'
}

# build_prompt <prompt-file> — prompt text plus issues and commit context.
build_prompt() {
  local prompt_file="$1"
  [[ -f "$prompt_file" ]] || die "prompt file not found: $prompt_file"
  cat "$prompt_file"
  printf '\n\n<issues>\n%s\n</issues>\n' "$(all_issues_block)"
  printf '\n<recent_commits>\n%s\n</recent_commits>\n' "$(recent_commits_block)"
}

# ------------------------------------------------------------------- agent call

# run_agent <model> — prompt on stdin, agent output on stdout.
run_agent() {
  local model="$1"
  # AGENT_ARGS lets you adapt to a different CLI without editing this file.
  local -a args
  if [[ -n "${AGENT_ARGS:-}" ]]; then
    read -r -a args <<< "$AGENT_ARGS"
  else
    args=(-p --permission-mode "$PERMISSION_MODE" --model "$model")
  fi
  "$AGENT_BIN" "${args[@]}"
}

init_logs() {
  mkdir -p "$LOG_DIR"
  RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
  export RUN_ID
}
