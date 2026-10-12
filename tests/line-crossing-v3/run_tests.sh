#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP_DIR="$ROOT/apps/line-crossing"
TESTS_DIR="$ROOT/tests/line-crossing-v3"
V2TESTS_DIR="$ROOT/tests/line-crossing-app"
EVIDENCE_DIR="$ROOT/docs/evidence/p7-line-crossing-v3"
CC=${CC:-cc}
CFLAGS="-Wall -Wextra -Werror -std=c11 -O2 -I$APP_DIR/include -I$APP_DIR/app -I$V2TESTS_DIR -I$TESTS_DIR"

step() { printf '\n== %s\n' "$*"; }
sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$EVIDENCE_DIR"
WORK="$TESTS_DIR/work"
mkdir -p "$WORK"

APP_SRCS="$APP_DIR/app/lc_app_entry_v3.c $APP_DIR/app/lc_bus.c $APP_DIR/app/lc_ctrl.c \
$APP_DIR/app/lc_bus_config.c $APP_DIR/app/lc_stateblob.c $APP_DIR/app/lc_cfgcodec.c \
$APP_DIR/app/lc_json.c $APP_DIR/app/lc_arena.c"
CORE_SRCS="$APP_DIR/src/lc_tracker.c $APP_DIR/src/lc_line_cross.c"
STUB="$V2TESTS_DIR/host_stub.c"

step "[1/8] v3 unit tests (candidate codec, state blob gen schema, host JSON boundary)"
"$CC" $CFLAGS "$TESTS_DIR/test_unit_v3.c" "$STUB" \
    "$APP_DIR/app/lc_cfgcodec.c" "$APP_DIR/app/lc_stateblob.c" \
    "$APP_DIR/app/lc_bus_config.c" \
    -o "$WORK/test_unit_v3"
"$WORK/test_unit_v3" | tee "$EVIDENCE_DIR/test-unit-v3.log"

step "[2/8] v3 control-plane transaction tests (AC1/AC2/AC3 incl. flush-defect fix)"
"$CC" $CFLAGS "$TESTS_DIR/test_ctrl_txn.c" "$STUB" $APP_SRCS $CORE_SRCS \
    -o "$WORK/test_ctrl_txn"
"$WORK/test_ctrl_txn" | tee "$EVIDENCE_DIR/test-ctrl-txn.log"

step "[3/8] v3 snapshot projection tests (AC4 incl. worst-case occupancy)"
"$CC" $CFLAGS "$TESTS_DIR/test_snapshot.c" "$STUB" $APP_SRCS $CORE_SRCS \
    -o "$WORK/test_snapshot"
"$WORK/test_snapshot" | tee "$EVIDENCE_DIR/test-snapshot.log"
grep -E "SNAPSHOT_OCCUPANCY" "$EVIDENCE_DIR/test-snapshot.log" || {
    echo "FAIL: snapshot occupancy line missing" >&2; exit 1; }

step "[4/8] v3 app_entry contract tests over stub v3 Host ABI (AC1/AC5 loop)"
"$CC" $CFLAGS "$TESTS_DIR/test_contract_v3.c" "$STUB" $APP_SRCS $CORE_SRCS \
    -o "$WORK/test_contract_v3"
"$WORK/test_contract_v3" | tee "$EVIDENCE_DIR/test-contract-v3.log"
grep -E "CONFIG_APPLY_OCCUPANCY" "$EVIDENCE_DIR/test-contract-v3.log" >/dev/null || {
    echo "FAIL: CONFIG_APPLY occupancy line missing" >&2; exit 1; }

step "[5/8] v2 full regression (v2 suite must stay green: business/contract/unit + native v2 package)"
bash "$V2TESTS_DIR/run_tests.sh" > "$EVIDENCE_DIR/v2-regression.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/v2-regression.log" >&2; exit 1; }
grep -E "RESULT: PASS" "$EVIDENCE_DIR/v2-regression.log" >/dev/null \
    || { echo "FAIL: v2 regression did not report PASS" >&2; exit 1; }
echo "OK: v2 suite PASS"

step "[6/8] native v3 image + signed v3 package + offline verification (pack and verify under --host-policy)"
if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    for d in /Applications/ArmGNUToolchain/*/arm-none-eabi/bin; do
        [ -x "$d/arm-none-eabi-gcc" ] && PATH="$d:$PATH" && break
    done
fi
command -v arm-none-eabi-gcc >/dev/null 2>&1 \
    || { echo "FAIL: arm-none-eabi-gcc not found" >&2; exit 1; }
make -C "$APP_DIR/app" clean-v3 > /dev/null 2>&1 || true
make -C "$APP_DIR/app" package-v3 > "$EVIDENCE_DIR/native-v3-package.log" 2>&1 \
    || { tail -30 "$EVIDENCE_DIR/native-v3-package.log" >&2; exit 1; }
grep -E "EXPECTED RESULT MATCH: PASS" "$EVIDENCE_DIR/native-v3-package.log" >/dev/null \
    || { echo "FAIL: v3 package verification did not PASS" >&2; exit 1; }
echo "OK: signed v3 package verified offline (default + host-policy tiers)"

step "[7/8] quota overflow rejection vectors at packaging layer (fail-closed)"
PKG="$WORK/pkg/lc-line-crossing-3.0.0.neapp.v3"
IMAGE="$APP_DIR/app/build/lc-line-crossing-v3.bin"
{
    echo "native_v3_image: $IMAGE"
    echo "native_v3_image_sha256: $(sha "$IMAGE")"
    echo "v3_package: $PKG"
    echo "v3_package_sha256: $(sha "$PKG")  (per-run dev-key signature; identity, not a pinned artifact)"
    echo "signing_identity: NON-PRODUCTION per-run dev key (tests/package/gen_dev_key.py), gitignored"
    echo "verifier: package/neapp_pack_v3.py --host-policy + package/neapp_verify_v3.py --policy --expect PASS (see native-v3-package.log)"
    echo "declared_quotas: control_max=256 snapshot_max=1024 event_max=2048 report_max=6144 state_quota=4096 caps=0xff profile=2"
    echo "measured_occupancy: CONFIG_APPLY_total=176B (<=256), worst_snapshot_total<=1024B (see test logs for exact worst-case numbers)"
    echo "boundary: offline packaging/verification only — no device install/execution/hot-config (v3 spec §14)"
} > "$EVIDENCE_DIR/native-v3-package-hashes.txt"

TIGHT_POLICY="$WORK/host_policy_reject.json"
python3 - "$TESTS_DIR/host_policy_sim.json" "$TIGHT_POLICY" << 'PYEOF'
import json, sys
policy = json.load(open(sys.argv[1]))
policy["control_msg_bytes"] = 175
policy["snapshot_ram_bytes"] = 980
json.dump(policy, open(sys.argv[2], "w"), indent=2)
PYEOF

if python3 "$ROOT/package/neapp_verify_v3.py" --package "$PKG" \
    --trust "$WORK/trust-dev.json" --policy "$TIGHT_POLICY" \
    --expect RESOURCE_LIMIT --compact > "$EVIDENCE_DIR/host-policy-reject.log" 2>&1 \
    && grep -q "RESOURCE_LIMIT" "$EVIDENCE_DIR/host-policy-reject.log"; then
    echo "OK: tightened Host policy (control 175 < 176 needed, snapshot 980 < 1024 declared) -> RESOURCE_LIMIT"
else
    echo "FAIL: tightened Host policy did not yield RESOURCE_LIMIT" >&2
    exit 1
fi

make -C "$APP_DIR/app" clean-v3 > /dev/null 2>&1 || true
if make -C "$APP_DIR/app" package-v3 V3_POLICY="$TIGHT_POLICY" \
    > "$EVIDENCE_DIR/pack-overflow-reject.log" 2>&1; then
    echo "FAIL: packer accepted declared quotas exceeding the target-Host policy" >&2
    exit 1
fi
grep -qiE "RESOURCE_LIMIT|control_max|snapshot_max" "$EVIDENCE_DIR/pack-overflow-reject.log" \
    || { echo "FAIL: packer rejection reason missing" >&2; exit 1; }
echo "OK: packer refuses declared control_max=256/snapshot_max=1024 against Host capacity 175/980 (fail-closed at pack time)"
make -C "$APP_DIR/app" package-v3 > /dev/null 2>&1

step "[8/8] frozen spec-v3 suite (container/wire/state-machine + M1-M11 cross-version rejections)"
python3 "$ROOT/tests/spec-v3/run_all_tests.py" > "$EVIDENCE_DIR/spec-v3-regression.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/spec-v3-regression.log" >&2; exit 1; }
grep -E "RESULT: PASS" "$EVIDENCE_DIR/spec-v3-regression.log" >/dev/null \
    || { echo "FAIL: frozen spec-v3 suite did not report PASS" >&2; exit 1; }
echo "OK: frozen spec-v3 suite PASS"

step "summary"
echo "evidence written under docs/evidence/p7-line-crossing-v3/:"
ls -1 "$EVIDENCE_DIR"
UNIT_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-unit-v3.log" | tail -1)
CTRL_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-ctrl-txn.log" | tail -1)
SNAP_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-snapshot.log" | tail -1)
CON_N=$(grep -oE "pass=[0-9]+" "$EVIDENCE_DIR/test-contract-v3.log" | tail -1)
printf '\nRESULT: PASS (%s, %s, %s, %s, v2 regression PASS)\n' "$UNIT_N" "$CTRL_N" "$SNAP_N" "$CON_N"
