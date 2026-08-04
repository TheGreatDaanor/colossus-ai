#!/usr/bin/env bash
#
# Scaffold a minimal TypeScript project so the kit has a working feedback loop.
#
# For greenfield repos only. The whole workflow rests on test/typecheck/lint being
# real commands that exit non-zero on failure — without them the agent is coding
# blind. This creates the smallest thing that satisfies that, shaped the way the
# rest of the kit expects: one deep module with a real test through its public
# interface.
#
# Deliberately minimal. It is a starting point for YOUR project, not a framework.
#
# Usage:
#   ./scripts/bootstrap-node.sh              # scaffold into the repo root
#   ./scripts/bootstrap-node.sh --pnpm       # use pnpm instead of npm
#   ./scripts/bootstrap-node.sh --dry-run

set -euo pipefail
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"
cd "$REPO_ROOT"

PM=npm
RUNNER=npx
DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pnpm) PM=pnpm; RUNNER="pnpm exec"; shift ;;
    --npm)  PM=npm;  RUNNER=npx; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

_c() { if [[ -t 1 ]]; then printf '\033[%sm' "$1"; fi; }
ok()   { _c '32'; printf '  + %s\n' "$*"; _c '0'; }
skip() { _c '2';  printf '  = %s (exists, left alone)\n' "$*"; _c '0'; }
warn() { _c '33'; printf 'warn: %s\n' "$*" >&2; _c '0'; }
die()  { _c '31'; printf 'error: %s\n' "$*" >&2; _c '0'; exit 1; }

command -v node >/dev/null || die "node not found — install Node 20+ first"
command -v "$PM" >/dev/null || die "$PM not found"

for f in package.json go.mod Cargo.toml pyproject.toml pom.xml; do
  [[ -f "$f" ]] && die "$f already exists — this script is for empty repos only"
done

write() {
  local path="$1"
  if [[ -e "$path" ]]; then skip "$path"; return; fi
  if (( DRY )); then ok "$path (dry run)"; return; fi
  mkdir -p "$(dirname "$path")"
  cat > "$path"
  ok "$path"
}

printf '\nscaffolding a TypeScript project in %s\n\n' "$REPO_ROOT"

# --------------------------------------------------------------- package.json
#
# The scripts here are the whole point. Each one:
#   - runs once and exits (vitest RUN, not watch)
#   - exits non-zero on failure
#   - needs no TTY and asks no questions
write package.json <<EOF
{
  "name": "$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "dev": "tsx watch src/index.ts",
    "build": "tsc -p tsconfig.build.json"
  },
  "devDependencies": {
    "@types/node": "^22.10.0",
    "eslint": "^9.17.0",
    "tsx": "^4.19.0",
    "typescript": "^5.7.0",
    "typescript-eslint": "^8.18.0",
    "vitest": "^2.1.0"
  }
}
EOF

# ---------------------------------------------------------------- tsconfig
write tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "types": ["node"],

    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "exactOptionalPropertyTypes": true,

    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,

    "noEmit": true,
    "outDir": "dist",
    "rootDir": "."
  },
  "include": ["src/**/*.ts", "*.config.ts"]
}
EOF

write tsconfig.build.json <<'EOF'
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "noEmit": false,
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src/**/*.ts"],
  "exclude": ["src/**/*.test.ts"]
}
EOF

# ------------------------------------------------------------------- eslint
write eslint.config.js <<'EOF'
// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**'],
  },
  {
    rules: {
      // Escape hatches are allowed, but must be justified in a comment. The
      // reviewer is told to flag any that are not.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
);
EOF

# ------------------------------------------------------------------- vitest
write vitest.config.ts <<'EOF'
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Tests live beside the code they test.
    include: ['src/**/*.test.ts'],
    environment: 'node',
    // No watch here. `npm test` must terminate — an unattended agent loop that
    // invokes a watching test runner hangs until its wall-clock cap.
    watch: false,
  },
});
EOF

# ----------------------------------------------------------- example module
#
# Shaped as a DEEP module on purpose: a small public interface with real logic
# behind it, tested through that interface rather than function by function.
# This is the shape the architecture skill will push you toward, so start there.
write src/services/points.ts <<'EOF'
/**
 * Points and levels.
 *
 * A deep module: small public surface (award, totalFor, levelFor), with the
 * rules living inside. Callers cannot reach past this interface, which is what
 * makes a single test boundary around it meaningful.
 */

export type PointEvent = {
  readonly userId: string;
  readonly kind: 'lesson_completed' | 'quiz_passed';
  readonly at: Date;
};

export type Level = {
  readonly number: number;
  readonly title: string;
  readonly pointsIntoLevel: number;
  readonly pointsToNext: number | null;
};

const POINTS_BY_KIND: Record<PointEvent['kind'], number> = {
  lesson_completed: 10,
  quiz_passed: 25,
};

const LEVEL_THRESHOLDS = [0, 100, 300, 600, 1000] as const;
const LEVEL_TITLES = ['Novice', 'Apprentice', 'Practitioner', 'Expert', 'Master'] as const;

export class PointsService {
  readonly #events: PointEvent[] = [];

  award(event: PointEvent): void {
    this.#events.push(event);
  }

  totalFor(userId: string): number {
    return this.#events
      .filter((e) => e.userId === userId)
      .reduce((sum, e) => sum + POINTS_BY_KIND[e.kind], 0);
  }

  levelFor(userId: string): Level {
    const total = this.totalFor(userId);

    let index = 0;
    for (let i = 0; i < LEVEL_THRESHOLDS.length; i += 1) {
      const threshold = LEVEL_THRESHOLDS[i];
      if (threshold !== undefined && total >= threshold) index = i;
    }

    const floor = LEVEL_THRESHOLDS[index] ?? 0;
    const next = LEVEL_THRESHOLDS[index + 1];

    return {
      number: index + 1,
      title: LEVEL_TITLES[index] ?? 'Unknown',
      pointsIntoLevel: total - floor,
      pointsToNext: next === undefined ? null : next - total,
    };
  }
}
EOF

# --------------------------------------------------------------- example test
#
# Note what this does NOT do: no mocks, no assertions on call counts, no test
# per internal function. It drives the public interface and asserts observable
# behaviour, so it survives refactoring and actually catches breakage.
write src/services/points.test.ts <<'EOF'
import { describe, expect, it } from 'vitest';
import { PointsService, type PointEvent } from './points.js';

const event = (over: Partial<PointEvent> = {}): PointEvent => ({
  userId: 'u1',
  kind: 'lesson_completed',
  at: new Date('2026-01-01T00:00:00Z'),
  ...over,
});

describe('PointsService', () => {
  it('awards 10 points for completing a lesson', () => {
    const svc = new PointsService();
    svc.award(event());
    expect(svc.totalFor('u1')).toBe(10);
  });

  it('awards 25 points for passing a quiz', () => {
    const svc = new PointsService();
    svc.award(event({ kind: 'quiz_passed' }));
    expect(svc.totalFor('u1')).toBe(25);
  });

  it('keeps each user’s points separate', () => {
    const svc = new PointsService();
    svc.award(event({ userId: 'u1' }));
    svc.award(event({ userId: 'u2', kind: 'quiz_passed' }));
    expect(svc.totalFor('u1')).toBe(10);
    expect(svc.totalFor('u2')).toBe(25);
  });

  it('starts a user with no events at level 1', () => {
    const svc = new PointsService();
    const level = svc.levelFor('nobody');
    expect(level.number).toBe(1);
    expect(level.title).toBe('Novice');
    expect(level.pointsToNext).toBe(100);
  });

  it('promotes to level 2 exactly at the 100 point threshold', () => {
    const svc = new PointsService();
    for (let i = 0; i < 4; i += 1) svc.award(event({ kind: 'quiz_passed' }));
    expect(svc.totalFor('u1')).toBe(100);
    expect(svc.levelFor('u1').number).toBe(2);
    expect(svc.levelFor('u1').pointsIntoLevel).toBe(0);
  });

  it('reports null pointsToNext at the maximum level', () => {
    const svc = new PointsService();
    for (let i = 0; i < 40; i += 1) svc.award(event({ kind: 'quiz_passed' }));
    const level = svc.levelFor('u1');
    expect(level.number).toBe(LEVEL_COUNT);
    expect(level.pointsToNext).toBeNull();
  });
});

const LEVEL_COUNT = 5;
EOF

write src/index.ts <<'EOF'
import { PointsService } from './services/points.js';

const points = new PointsService();
points.award({ userId: 'demo', kind: 'lesson_completed', at: new Date() });

console.warn(`demo has ${points.totalFor('demo')} points`);
console.warn(`level: ${points.levelFor('demo').title}`);
EOF

write .gitignore <<'EOF'
node_modules/
dist/
coverage/
*.log
.env
.env.*
!.env.example

# agent workflow
.agent-logs/
.afk-worktrees/
EOF

# -------------------------------------------------------- CLAUDE.md commands

if (( ! DRY )) && [[ -f CLAUDE.md ]]; then
  tmp="$(mktemp)"
  sed \
    -e 's|^- Test: `.*`$|- Test: `npm test`|' \
    -e 's|^- Typecheck: `.*`$|- Typecheck: `npm run typecheck`|' \
    -e 's|^- Lint: `.*`$|- Lint: `npm run lint`|' \
    -e 's|^- Dev server: `.*`$|- Dev server: `npm run dev`|' \
    -e 's|^Scoped test run (single module, for tight loops): `.*`$|Scoped test run (single module, for tight loops): `npx vitest run src/services/points`|' \
    -e 's|^- Never edit files under `.*` (generated)\.$|- Never edit files under `dist/` (generated).|' \
    CLAUDE.md > "$tmp"
  mv "$tmp" CLAUDE.md
  ok "CLAUDE.md commands updated"
fi

printf '\n'
if (( DRY )); then
  warn "dry run — nothing written"
  exit 0
fi

_c '1'; printf 'installing dependencies (%s)\n' "$PM"; _c '0'
$PM install

printf '\n'
_c '1'; printf 'verifying the feedback loop\n'; _c '0'
failed=0
for s in test typecheck lint; do
  if $PM run "$s" >/dev/null 2>&1; then
    ok "$PM run $s exits 0"
  else
    warn "$PM run $s failed — see: $PM run $s"
    failed=1
  fi
done

printf '\n'
if (( failed )); then
  warn "fix the failures above, then run ./scripts/doctor.sh"
else
  _c '32'; printf 'done.\n'; _c '0'
  cat <<'EOF'

The three commands now exist, run once, and exit non-zero on failure. That is
the feedback loop the whole workflow depends on.

Next:
  ./scripts/doctor.sh          should now be green on step 1

  Then fill in the Architecture section of CLAUDE.md (2-3 lines about
  src/services/ being where the deep modules live), and start a feature:

    claude
    > /grill-me
EOF
fi
