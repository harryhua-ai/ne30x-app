#!/usr/bin/env bash
# run_tests.sh — offline build + equivalence tests for the ported
# line-crossing core (Harry Dev Issue #8, P7 core).
#
# What it does (default: fully offline, no ne301 checkout needed):
#   [1/4] build the ported core library (apps/line-crossing)
#   [2/4] build & run the VERBATIM upstream regression test
#         (ne301 counting@de25a6f1 tests/host/test_lc_engine.c)
#         against the ported core -> must pass unchanged
#   [3/4] build & run the deterministic equivalence harness against
#         the ported core and diff its trace against the committed
#         golden trace (generated from the pinned upstream sources)
#   [4/4] write evidence logs under docs/evidence/p7-line-crossing/
#
# Optional modes (require the pinned ne301 checkout, default
# ../../ne301 relative to the repo root, override with NE301_SRC):
#   ./run_tests.sh --regen-golden   regenerate the golden trace from
#                                   the pinned upstream sources
#   ./run_tests.sh --provenance     live provenance check: diff ported
#                                   files against upstream and rebuild
#                                   the harness against upstream, then
#                                   re-diff traces live
#
# Exit non-zero on the first failed step.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TESTS_DIR="$ROOT/tests/line-crossing"
APP_DIR="$ROOT/apps/line-crossing"
EVIDENCE_DIR="$ROOT/docs/evidence/p7-line-crossing"
GOLDEN="$TESTS_DIR/golden/lc_equiv_trace.expected.txt"
# Optional modes need the pinned ne301 checkout (counting@de25a6f1).
# Override with NE301_SRC=<path>.  Auto-detected candidates cover the
# .worktree layout and a plain sibling clone.
NE301_SRC="${NE301_SRC:-}"
if [ -z "$NE301_SRC" ]; then
    for cand in "$ROOT/../../../ne301" "$ROOT/../ne301"; do
        if [ -f "$cand/Custom/Tasks/Src/lc_tracker.c" ]; then
            NE301_SRC=$(cd "$cand" && pwd)
            break
        fi
    done
fi

CC=${CC:-cc}
CFLAGS="-Wall -Wextra -Werror -std=c11 -O2"

step() { printf '\n== %s\n' "$*"; }

mkdir -p "$EVIDENCE_DIR"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

MODE="test"
for arg in "$@"; do
    case "$arg" in
        --regen-golden) MODE="regen-golden" ;;
        --provenance)   MODE="provenance" ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

UPSTREAM_INC="-I$NE301_SRC/Custom/Tasks/Inc"
UPSTREAM_SRC="$NE301_SRC/Custom/Tasks/Src/lc_tracker.c $NE301_SRC/Custom/Tasks/Src/lc_line_cross.c"

require_upstream() {
    if [ ! -f "$NE301_SRC/Custom/Tasks/Src/lc_tracker.c" ]; then
        echo "FAIL: pinned ne301 checkout not found at $NE301_SRC" >&2
        echo "      (set NE301_SRC=... to the counting@de25a6f1 checkout)" >&2
        exit 3
    fi
}

step "[1/4] build ported core library"
{ make -C "$APP_DIR" clean all
  "$CC" $CFLAGS -I"$APP_DIR/include" -c "$TESTS_DIR/test_lc_engine.c" -o "$WORK/test_lc_engine.o"
  "$CC" $CFLAGS -I"$APP_DIR/include" -c "$TESTS_DIR/lc_equiv_harness.c" -o "$WORK/harness.o"
} > "$EVIDENCE_DIR/build.log" 2>&1
cat "$EVIDENCE_DIR/build.log"
echo "OK: library and test objects build clean (-Wall -Wextra -Werror -std=c11)"

step "[2/4] upstream regression test (verbatim test_lc_engine.c) vs ported core"
"$CC" $CFLAGS -I"$APP_DIR/include" \
    "$TESTS_DIR/test_lc_engine.c" \
    "$APP_DIR/src/lc_tracker.c" "$APP_DIR/src/lc_line_cross.c" \
    -lm -o "$WORK/test_lc_engine"
"$WORK/test_lc_engine" | tee "$EVIDENCE_DIR/test_lc_engine.log"
grep -q "^all lc engine tests passed$" "$EVIDENCE_DIR/test_lc_engine.log" \
    || { echo "FAIL: upstream regression test did not pass" >&2; exit 1; }

step "[3/4] equivalence trace vs committed golden"
"$CC" $CFLAGS -I"$APP_DIR/include" \
    "$TESTS_DIR/lc_equiv_harness.c" \
    "$APP_DIR/src/lc_tracker.c" "$APP_DIR/src/lc_line_cross.c" \
    -lm -o "$WORK/harness_ported"
"$WORK/harness_ported" > "$WORK/trace_ported.txt"
cp "$WORK/trace_ported.txt" "$EVIDENCE_DIR/equiv-trace-ported.log"

if [ "$MODE" = "regen-golden" ]; then
    require_upstream
    step "[regen] build harness against pinned upstream sources"
    "$CC" $CFLAGS -D__LC_TEST__ $UPSTREAM_INC \
        "$TESTS_DIR/lc_equiv_harness.c" $UPSTREAM_SRC \
        -lm -o "$WORK/harness_upstream"
    "$WORK/harness_upstream" > "$GOLDEN" 2> "$EVIDENCE_DIR/golden-regen.log"
    echo "golden regenerated at $GOLDEN from $NE301_SRC"
fi

if [ ! -f "$GOLDEN" ]; then
    echo "FAIL: golden trace missing: $GOLDEN" >&2
    exit 1
fi

if diff -u "$GOLDEN" "$WORK/trace_ported.txt" > "$WORK/equiv.diff"; then
    {
        echo "golden: $GOLDEN"
        echo "ported: harness trace (apps/line-crossing core)"
        echo "diff: IDENTICAL"
        echo "sha256 golden: $(shasum -a 256 "$GOLDEN" | awk '{print $1}')"
        echo "sha256 ported: $(shasum -a 256 "$WORK/trace_ported.txt" | awk '{print $1}')"
    } | tee "$EVIDENCE_DIR/equiv-diff.log"
    echo "OK: ported core trace is byte-identical to the upstream golden trace"
else
    cp "$WORK/equiv.diff" "$EVIDENCE_DIR/equiv-diff.log"
    echo "FAIL: equivalence trace differs from golden" >&2
    cat "$WORK/equiv.diff" >&2
    exit 1
fi

if [ "$MODE" = "provenance" ]; then
    step "[provenance] diff ported sources against pinned upstream"
    require_upstream
    {
        diff -u "$NE301_SRC/Custom/Tasks/Inc/lc_types.h"      "$APP_DIR/include/lc_types.h"      || true
        diff -u "$NE301_SRC/Custom/Tasks/Inc/lc_line_cross.h" "$APP_DIR/include/lc_line_cross.h" || true
        diff -u "$NE301_SRC/Custom/Tasks/Inc/lc_tracker.h"    "$APP_DIR/include/lc_tracker.h"    || true
        diff -u "$NE301_SRC/Custom/Tasks/Src/lc_tracker.c"    "$APP_DIR/src/lc_tracker.c"        || true
        diff -u "$NE301_SRC/Custom/Tasks/Src/lc_line_cross.c" "$APP_DIR/src/lc_line_cross.c"     || true
        diff -u "$NE301_SRC/tests/host/test_lc_engine.c"      "$TESTS_DIR/test_lc_engine.c"      || true
    } > "$EVIDENCE_DIR/provenance.patch"
    echo "provenance diff written to $EVIDENCE_DIR/provenance.patch"
    echo "--- changed regions (expect only the lc_types.h allocator seam) ---"
    grep -c '^[-+]' "$EVIDENCE_DIR/provenance.patch" || true

    step "[provenance] rebuild harness against upstream and re-diff live"
    "$CC" $CFLAGS -D__LC_TEST__ $UPSTREAM_INC \
        "$TESTS_DIR/lc_equiv_harness.c" $UPSTREAM_SRC \
        -lm -o "$WORK/harness_upstream"
    "$WORK/harness_upstream" > "$WORK/trace_upstream.txt"
    if diff -u "$WORK/trace_upstream.txt" "$WORK/trace_ported.txt" > "$WORK/live.diff"; then
        echo "OK: live upstream trace is byte-identical to ported trace"
    else
        echo "FAIL: live upstream trace differs" >&2
        cat "$WORK/live.diff" >&2
        exit 1
    fi
fi

step "[4/4] evidence"
echo "evidence written under $EVIDENCE_DIR:"
ls -1 "$EVIDENCE_DIR"
printf '\nRESULT: PASS\n'
