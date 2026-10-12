#!/usr/bin/env bash
set -euo pipefail

ROOT=${1:?usage: require_clean_evidence.sh <repo-root>}

GUARDED=(
    docs/evidence/p3-package-artifacts.json
    docs/evidence/p6-package-checks.log
    docs/evidence/p6-package-artifacts.json
    docs/evidence/p6-v1-regression-artifacts.json
    docs/evidence/p6-package-v3-checks.log
    docs/evidence/p6-package-v3-artifacts.json
    docs/evidence/spec-v2
    docs/evidence/spec-v3
)

dirty=""
for rel in "${GUARDED[@]}"; do
    entry=$(git -C "$ROOT" status --porcelain -- "$rel")
    if [ -n "$entry" ]; then
        dirty+="  $rel
"
    fi
done

if [ -n "$dirty" ]; then
    echo "FAIL: refuse to run: guarded evidence files already have uncommitted changes:" >&2
    printf '%s' "$dirty" >&2
    echo "The frozen v1/v2 regression, the spec-v2/spec-v3 suites and this script" >&2
    echo "rewrite these files (and restore or regenerate them) while running; starting" >&2
    echo "now would silently discard those edits.  Commit or stash them first, then" >&2
    echo "re-run.  Nothing was executed and nothing was modified." >&2
    exit 1
fi
echo "evidence guard: all guarded evidence files are in committed-clean state (fail-closed pre-check passed)"
