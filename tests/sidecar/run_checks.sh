#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tests/sidecar/work"
LOG="$ROOT/docs/evidence/sidecar-v1/sidecar-v1-checks.log"
PYTHON=${PYTHON:-python3}

OWNED=(
    docs/evidence/sidecar-v1
)
NATIVE_OWNED=(
    docs/evidence/p3-package-artifacts.json
    docs/evidence/p6-package-checks.log
    docs/evidence/p6-package-artifacts.json
    docs/evidence/p6-v1-regression-artifacts.json
    docs/evidence/p6-package-v3-checks.log
    docs/evidence/p6-package-v3-artifacts.json
)

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}
restore_native_evidence() {
    git -C "$ROOT" restore -- "${NATIVE_OWNED[@]}"
    for rel in "${NATIVE_OWNED[@]}"; do
        [ -z "$(git -C "$ROOT" status --porcelain -- "$rel")" ] \
            || fail "$rel is not clean after restore"
    done
    echo "native-owned evidence files restored byte-identical (regression observed, no churn)"
}

for rel in "${OWNED[@]}" "${NATIVE_OWNED[@]}"; do
    entry=$(git -C "$ROOT" status --porcelain -- "$rel")
    if [ -n "$entry" ]; then
        echo "FAIL: refuse to run: $rel already has uncommitted changes:" >&2
        printf '%s\n' "$entry" >&2
        echo "Commit or restore it first; nothing was executed." >&2
        exit 1
    fi
done

mkdir -p "$ROOT/docs/evidence/sidecar-v1"
exec > >(tee "$LOG") 2>&1

step "[1/6] preflight"
command -v "$PYTHON" >/dev/null || fail "python3 missing"
"$PYTHON" -c 'import cryptography' 2>/dev/null || fail "python cryptography missing"
command -v openssl >/dev/null || fail "openssl missing"
echo "python3=$($PYTHON --version 2>&1) cryptography=$($PYTHON -c 'import cryptography; print(cryptography.__version__)') openssl=$(openssl version 2>&1 | awk '{print $1 $2}')"
rm -rf "$WORK"
mkdir -p "$WORK"

step "[2/6] native v1 pack/verify suite UNCHANGED (tests/package/run_package_checks.sh)"
bash "$ROOT/tests/package/run_package_checks.sh" > "$WORK/native-v1-suite.log" 2>&1 \
    || { tail -40 "$WORK/native-v1-suite.log"; fail "native v1 suite regressed"; }
tail -6 "$WORK/native-v1-suite.log"
restore_native_evidence

step "[3/6] native v2 pack/verify suite UNCHANGED (tests/package-v2/run_checks.sh)"
bash "$ROOT/tests/package-v2/run_checks.sh" > "$WORK/native-v2-suite.log" 2>&1 \
    || { tail -40 "$WORK/native-v2-suite.log"; fail "native v2 suite regressed"; }
tail -6 "$WORK/native-v2-suite.log"
restore_native_evidence

step "[4/6] native v3 pack/verify suite UNCHANGED (tests/package-v3/run_checks.sh)"
bash "$ROOT/tests/package-v3/run_checks.sh" > "$WORK/native-v3-suite.log" 2>&1 \
    || { tail -40 "$WORK/native-v3-suite.log"; fail "native v3 suite regressed"; }
tail -6 "$WORK/native-v3-suite.log"
restore_native_evidence

step "[5/6] frozen spec suites UNCHANGED (spec-v2, spec-v3; evidence must stay deterministic)"
"$PYTHON" "$ROOT/tests/spec-v2/run_all_tests.py" >/dev/null \
    || fail "tests/spec-v2 run_all_tests.py failed"
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v2 \
    || fail "tests/spec-v2 run_all_tests.py rewrote the committed evidence"
echo "spec-v2 suite: PASS (committed evidence byte-identical)"
"$PYTHON" "$ROOT/tests/spec-v3/run_all_tests.py" >/dev/null \
    || fail "tests/spec-v3 run_all_tests.py failed"
git -C "$ROOT" diff --quiet -- docs/evidence/spec-v3 \
    || fail "tests/spec-v3 run_all_tests.py rewrote the committed evidence"
echo "spec-v3 suite: PASS (committed evidence byte-identical)"

step "[6/6] sidecar v1 case suite (AC1/AC2/AC3) + golden byte-identity + evidence"
"$PYTHON" "$ROOT/tests/sidecar/neui_cases.py" \
    --work-dir "$WORK" \
    --golden-dir "$ROOT/docs/evidence/sidecar-v1"

python3 - "$ROOT" "$WORK" <<'EOF'
import json, subprocess, sys
from pathlib import Path

root, work = Path(sys.argv[1]), Path(sys.argv[2])
suite_results = json.loads((work / "neui-cases-results.json").read_text())
report = json.loads((root / "docs" / "evidence" / "sidecar-v1" / "report.json").read_text())

def git(*args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          text=True, check=True).stdout.strip()

regression = {
    "issue": "harryhua-ai/ne30x-app#26 (AC4 native regression)",
    "boundary": ("native v1/v2/v3 pack/verify/spec suites re-run UNCHANGED from this branch; "
                 "their owned docs/evidence files were pre-checked committed-clean, then "
                 "restored byte-identical after each run"),
    "source_commit": git("rev-parse", "HEAD"),
    "suites": {
        "tests/package/run_package_checks.sh": {
            "result": "PASS (exit 0)", "log": "tests/sidecar/work/native-v1-suite.log"},
        "tests/package-v2/run_checks.sh": {
            "result": "PASS (exit 0)", "log": "tests/sidecar/work/native-v2-suite.log"},
        "tests/package-v3/run_checks.sh": {
            "result": "PASS (exit 0)",
            "note": ("internally re-runs the v1 regression, tests/package-v2/run_checks.sh, "
                     "tests/spec-v2 and tests/spec-v3"),
            "log": "tests/sidecar/work/native-v3-suite.log"},
        "tests/spec-v2/run_all_tests.py": {
            "result": "PASS (exit 0, committed evidence byte-identical)"},
        "tests/spec-v3/run_all_tests.py": {
            "result": "PASS (exit 0, committed evidence byte-identical)"},
    },
    "owned_evidence_restored_byte_identical": True,
}
out = root / "docs" / "evidence" / "sidecar-v1" / "regression.json"
out.write_text(json.dumps(regression, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
report["native_regression"] = regression
(root / "docs" / "evidence" / "sidecar-v1" / "report.json").write_text(
    json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"native regression summary -> {out}")
print(f"sidecar case suite total: {len(suite_results)} entries, all expectations matched")
EOF

printf '\n== ALL SIDECAR V1 CHECKS PASSED\n'
printf 'golden bundle  docs/evidence/sidecar-v1/golden.neui\n  sha256 %s\n' "$(sha "$ROOT/docs/evidence/sidecar-v1/golden.neui")"
printf 'evidence log   %s\n' "$LOG"
