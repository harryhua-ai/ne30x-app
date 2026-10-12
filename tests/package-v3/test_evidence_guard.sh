#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GUARD="$ROOT/tests/package-v3/require_clean_evidence.sh"
RUN_CHECKS="$ROOT/tests/package-v3/run_checks.sh"

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

TMP=$(mktemp -d)
SAVED=$(mktemp)
LOG="$ROOT/docs/evidence/p6-package-checks.log"
cleanup() {
    if [ -s "$SAVED" ]; then cp "$SAVED" "$LOG"; fi
    rm -f "$SAVED"
    rm -rf "$TMP"
}
trap cleanup EXIT

step "[1/4] isolated clean repo: guard accepts"
git -C "$TMP" init -q
git -C "$TMP" config user.email guard-regression@test.local
git -C "$TMP" config user.name guard-regression
mkdir -p "$TMP/docs/evidence"
for rel in docs/evidence/p3-package-artifacts.json \
           docs/evidence/p6-package-checks.log \
           docs/evidence/p6-package-artifacts.json \
           docs/evidence/p6-v1-regression-artifacts.json \
           docs/evidence/p6-package-v3-checks.log \
           docs/evidence/p6-package-v3-artifacts.json; do
    printf 'committed-bytes\n' > "$TMP/$rel"
done
mkdir -p "$TMP/docs/evidence/spec-v2" "$TMP/docs/evidence/spec-v3"
printf 'committed-bytes\n' > "$TMP/docs/evidence/spec-v2/report.json"
printf 'committed-bytes\n' > "$TMP/docs/evidence/spec-v3/report.json"
git -C "$TMP" add -A
git -C "$TMP" commit -qm "guarded evidence baseline"
bash "$GUARD" "$TMP" || fail "guard rejected a fully clean repo"
echo "guard accepted the clean repo"

step "[2/4] uncommitted worktree modification: guard fails closed, caller bytes survive"
printf 'caller-uncommitted-work\n' >> "$TMP/docs/evidence/p6-package-checks.log"
if bash "$GUARD" "$TMP" >/dev/null 2>&1; then
    fail "guard accepted a repo with an uncommitted modification"
fi
grep -q 'caller-uncommitted-work' "$TMP/docs/evidence/p6-package-checks.log" \
    || fail "guard modified the caller's uncommitted content"
echo "guard refused the dirty repo; the uncommitted caller bytes are intact"

step "[3/4] staged-only modification: guard fails closed"
printf 'caller-staged-work\n' > "$TMP/docs/evidence/p6-package-artifacts.json"
git -C "$TMP" add docs/evidence/p6-package-artifacts.json
if bash "$GUARD" "$TMP" >/dev/null 2>&1; then
    fail "guard accepted a repo with a staged-only modification"
fi
git -C "$TMP" reset -q docs/evidence/p6-package-artifacts.json
git -C "$TMP" checkout -q -- docs/evidence/p6-package-artifacts.json
echo "guard refused the staged-only modification"

step "[4/4] real repo: run_checks.sh fail-closes fast on a dirty guarded file (probe self-restored)"
[ -f "$LOG" ] || fail "real-repo probe requires the committed $LOG"
cp "$LOG" "$SAVED"
printf 'guard-regression-probe\n' >> "$LOG"
OUT=$(mktemp)
if RUN_CHECKS_CHILD=1 bash "$RUN_CHECKS" >"$OUT" 2>&1; then
    rm -f "$OUT"
    fail "run_checks.sh did not fail closed on a dirty guarded evidence file"
fi
grep -q 'guard-regression-probe' "$LOG" \
    || fail "run_checks.sh destroyed the probe modification instead of refusing to run"
grep -q 'uncommitted changes' "$OUT" \
    || fail "run_checks.sh refusal lacks the fail-closed guidance"
grep -q 'p6-package-checks.log' "$OUT" \
    || fail "run_checks.sh refusal does not name the offending guarded file"
rm -f "$OUT"
cp "$SAVED" "$LOG"
: > "$SAVED"
if git -C "$ROOT" status --porcelain -- docs/evidence/p6-package-checks.log | grep -q .; then
    fail "probe restoration left $LOG dirty"
fi
echo "run_checks.sh refused to start with guidance; probe restored byte-identical"

printf '\n== EVIDENCE GUARD NON-DESTRUCTIVE REGRESSION PASSED\n'
