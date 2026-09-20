#!/usr/bin/env bash
#
# Start the server, create a program, enumerate it, and run a scan against it.
#
# The end-to-end path a human needs to eyeball the app: it leaves a program and
# a finished scan behind, and prints the inventory view that issue 039 asks a
# human to confirm reads as facts rather than as defects.
#
# Usage: ./scripts/walkthrough.sh [--url URL] [--keep] [--simulate-new HOST]
#
#   --url            the program's root URL. Defaults to https://example.com.
#   --keep           leave the server running on exit (default: stop it).
#   --simulate-new   insert HOST between the two enumerations, so the second one
#                    has a host to mark is_new. A review aid for issue 039: the
#                    real CT log answers the same set twice in a row, which is
#                    correct but shows a reviewer nothing. Writes straight to the
#                    SQLite file; nothing in src/ knows about it.
#
# Scans are PASSIVE here: the scanner fetches the target and reads what comes
# back. Only point it at a host you are authorized to test. Active mode needs an
# explicit confirmAuthorized and is deliberately not wired into this script.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

URL="https://example.com"
KEEP=0
SIMULATE_NEW=""
PORT="${PORT:-3000}"
BASE="http://localhost:${PORT}"
DB_PATH="${DB_PATH:-./data/scanner.db}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --simulate-new) SIMULATE_NEW="$2"; shift 2 ;;
    --host) # a likely mix-up: --simulate-new is not how you choose the target
      printf 'unknown argument: --host. To choose what gets scanned, use --url.\n' >&2; exit 1 ;;
    -h|--help) sed -n '2,23p' "$0" | sed 's/^#//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

for cmd in curl python3; do
  command -v "$cmd" >/dev/null || { printf 'error: %s is required\n' "$cmd" >&2; exit 1; }
done

# --simulate-new names a host to plant in the inventory; --url names what gets
# scanned. Passing a URL to the former is the easy mix-up, and it is silent —
# the run scans the default target and plants a host nothing will ever match.
if [[ "$SIMULATE_NEW" == *://* ]]; then
  printf 'error: --simulate-new takes a hostname, not a URL (got %s).\n' "$SIMULATE_NEW" >&2
  printf '       To choose what gets scanned:  --url %s\n' "$SIMULATE_NEW" >&2
  printf '       To plant a host in the inventory:  --simulate-new %s\n' "${SIMULATE_NEW#*://}" >&2
  exit 1
fi

# Pull one field out of a JSON response. python3 rather than jq: jq is not a
# dependency of this repo and python3 already is, via the tooling scripts.
json_field() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get(sys.argv[1])) if not isinstance(d.get(sys.argv[1]),(str,int,float)) or isinstance(d.get(sys.argv[1]),bool) else d[sys.argv[1]])' "$1"
}

SERVER_PID=""
STARTED_SERVER=0
LOG="$(mktemp -t colossus-walkthrough.XXXXXX.log)"

cleanup() {
  if (( STARTED_SERVER )) && (( ! KEEP )) && [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    printf '\n[cleanup] stopped the server (pid %s)\n' "$SERVER_PID"
  elif (( STARTED_SERVER )) && (( KEEP )); then
    printf '\n[cleanup] server left running on %s (pid %s); log: %s\n' "$BASE" "$SERVER_PID" "$LOG"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- step 1: serve
if curl -fsS -o /dev/null "${BASE}/scans" 2>/dev/null; then
  printf '[1/5] server already listening on %s — reusing it\n' "$BASE"
else
  printf '[1/5] starting the server (npm run dev)...\n'
  npm run dev >"$LOG" 2>&1 &
  SERVER_PID=$!
  STARTED_SERVER=1

  # tsx watch compiles before it listens; that took ~8s on the machine this was
  # written on, which is why a naive curl straight after `npm run dev` fails.
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "${BASE}/scans" 2>/dev/null; then break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      printf 'error: server exited during startup. Log:\n' >&2
      cat "$LOG" >&2
      exit 1
    fi
    sleep 1
  done

  curl -fsS -o /dev/null "${BASE}/scans" 2>/dev/null || {
    printf 'error: server did not become ready within 60s. Log:\n' >&2
    cat "$LOG" >&2
    exit 1
  }
  printf '      up on %s (pid %s)\n' "$BASE" "$SERVER_PID"
fi

# -------------------------------------------------------------- step 2: program
printf '[2/5] creating a program for %s...\n' "$URL"
PROGRAM_JSON="$(curl -fsS -X POST "${BASE}/programs" \
  -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"url": sys.argv[1]}))' "$URL")")"
PROGRAM_ID="$(printf '%s' "$PROGRAM_JSON" | json_field id)"
printf '      program id=%s\n' "$PROGRAM_ID"

# Creating a program from a URL infers a scope entry for the whole domain, but
# leaves it unconfirmed: confirming is what authorizes enumeration to widen from
# the one submitted host to the domain. Without this the inventory stays empty.
printf '[3/5] confirming inferred scope entries...\n'
ENTRY_IDS="$(printf '%s' "$PROGRAM_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for e in d.get("scope_entries") or []:
    # An in-scope entry with no confirmed_at is the inferred one awaiting a
    # deliberate confirmation; out-of-scope entries are never enumerated from.
    if e.get("list") == "in" and e.get("confirmed_at") is None:
        print(e["id"])
')"
if [[ -z "$ENTRY_IDS" ]]; then
  printf '      (none needed confirming)\n'
else
  for entry in $ENTRY_IDS; do
    curl -fsS -o /dev/null -X POST "${BASE}/programs/${PROGRAM_ID}/scope/${entry}/confirm"
    printf '      confirmed scope entry %s\n' "$entry"
  done
fi

# ------------------------------------------------------------ step 4: enumerate
# Twice: one enumeration stamps every host with the same first-seen time, so a
# single run marks nothing new. The second run is what gives `is_new` something
# to say — the view issue 039 wants a human to read.
printf '[4/5] enumerating the inventory (twice, so is_new has meaning)...\n'
for run in 1 2; do
  ENUM="$(curl -fsS -X POST "${BASE}/programs/${PROGRAM_ID}/enumerate" \
    -H 'content-type: application/json' -d '{}')"
  COUNT="$(printf '%s' "$ENUM" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("hosts") or []))')"
  ERR="$(printf '%s' "$ENUM" | json_field enumeration_error)"
  printf '      run %s: %s host(s), enumeration_error=%s\n' "$run" "$COUNT" "$ERR"

  # A CT-log outage is recorded on the program rather than thrown, so the run
  # keeps going with whatever inventory already existed. That is correct, and it
  # is also easy to read straight past when the answer is an empty inventory.
  if [[ "$ERR" != "null" ]]; then
    printf '      ^ the CT source failed. The inventory is whatever was already\n'
    printf '        there, so this run shows nothing new. Usually transient —\n'
    printf '        crt.sh 502s under load. Re-run in a minute.\n'
  fi

  # Enumeration reads a real CT log, which answers the same set twice in a row.
  # With nothing new, every host is is_new=false and new_since is null — correct,
  # but it shows the reviewer none of what issue 039 built. This inserts a host
  # between the runs so the second one has something to mark. It is a review aid,
  # not part of the feature: nothing in src/ knows about it.
  if (( run == 1 )) && [[ -n "$SIMULATE_NEW" ]]; then
    printf '      [--simulate-new] inserting %s ahead of run 2\n' "$SIMULATE_NEW"
    python3 - "$DB_PATH" "$PROGRAM_ID" "$SIMULATE_NEW" <<'PYEOF'
import sqlite3, sys, time
db, program_id, hostname = sys.argv[1], int(sys.argv[2]), sys.argv[3]
con = sqlite3.connect(db)
# One second later than the run-1 rows, which is what makes it a distinct
# first-seen value: the service reads newness off those values, stored to the second.
latest = con.execute(
    "SELECT MAX(first_seen_at) FROM enumerated_hosts WHERE program_id = ?", (program_id,)
).fetchone()[0] or int(time.time())
con.execute(
    "INSERT OR IGNORE INTO enumerated_hosts"
    " (program_id, hostname, source, scope_status, is_wildcard, failed_resolutions, first_seen_at)"
    " VALUES (?, ?, 'ct-log', 'in_scope', 0, 0, ?)",
    (program_id, hostname, latest + 1),
)
con.commit()
con.close()
PYEOF
  fi
done

printf '\n      --- inventory view (GET /programs/%s/hosts) ---\n' "$PROGRAM_ID"
curl -fsS "${BASE}/programs/${PROGRAM_ID}/hosts" | python3 -m json.tool
printf '      --- end inventory view ---\n\n'

# ----------------------------------------------------------------- step 5: scan
printf '[5/5] starting a passive scan against %s...\n' "$URL"
SCAN_JSON="$(curl -fsS -X POST "${BASE}/scans" \
  -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"urls":[sys.argv[1]],"programId":int(sys.argv[2]),"mode":"passive","name":"walkthrough"}))' "$URL" "$PROGRAM_ID")")"
SCAN_ID="$(printf '%s' "$SCAN_JSON" | json_field id)"
printf '      scan id=%s — polling until it completes...\n' "$SCAN_ID"

# A scan runs on a background task, so the POST returns before there is anything
# to read. Same wait the test suite does, with the same generous budget.
for _ in $(seq 1 60); do
  STATUS="$(curl -fsS "${BASE}/scans/${SCAN_ID}" | json_field status)"
  [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
  sleep 1
done
printf '      scan status: %s\n' "$STATUS"

printf '\n      --- scan result (GET /scans/%s) ---\n' "$SCAN_ID"
curl -fsS "${BASE}/scans/${SCAN_ID}" | python3 -m json.tool
printf '      --- end scan result ---\n'

printf '\nDone. Things to look at:\n'
printf '  program    %s/programs/%s\n' "$BASE" "$PROGRAM_ID"
printf '  inventory  %s/programs/%s/hosts   <- the issue-039 view\n' "$BASE" "$PROGRAM_ID"
printf '  scan       %s/scans/%s\n' "$BASE" "$SCAN_ID"
printf '  dashboard  %s/dashboard/scans/%s\n' "$BASE" "$SCAN_ID"
