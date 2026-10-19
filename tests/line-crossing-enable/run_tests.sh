#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP_DIR="$ROOT/apps/line-crossing"
TEST_DIR="$ROOT/tests/line-crossing-enable"
STUB_DIR="$ROOT/tests/line-crossing-app"
CC=${CC:-cc}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/line-crossing-enable.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

CFLAGS="-Wall -Wextra -Werror -std=c11 -O2 -I$APP_DIR/include -I$APP_DIR/app -I$STUB_DIR"

"$CC" $CFLAGS \
    "$TEST_DIR/test_enable.c" \
    "$STUB_DIR/host_stub.c" \
    "$APP_DIR/app/lc_app_entry.c" \
    "$APP_DIR/app/lc_bus.c" \
    "$APP_DIR/app/lc_bus_config.c" \
    "$APP_DIR/app/lc_stateblob.c" \
    "$APP_DIR/app/lc_ctrl.c" \
    "$APP_DIR/app/lc_cfgcodec.c" \
    "$APP_DIR/app/lc_json.c" \
    "$APP_DIR/app/lc_arena.c" \
    "$APP_DIR/src/lc_tracker.c" \
    "$APP_DIR/src/lc_line_cross.c" \
    -o "$WORK/test_enable"

"$WORK/test_enable"

"$CC" $CFLAGS \
    "$TEST_DIR/test_v4_entry.c" \
    "$STUB_DIR/host_stub.c" \
    "$APP_DIR/app/lc_app_entry_v4.c" \
    "$APP_DIR/app/lc_bus.c" \
    "$APP_DIR/app/lc_bus_config.c" \
    "$APP_DIR/app/lc_stateblob.c" \
    "$APP_DIR/app/lc_ctrl.c" \
    "$APP_DIR/app/lc_cfgcodec.c" \
    "$APP_DIR/app/lc_json.c" \
    "$APP_DIR/app/lc_arena.c" \
    "$APP_DIR/app/lc_lvn4.c" \
    "$APP_DIR/src/lc_tracker.c" \
    "$APP_DIR/src/lc_line_cross.c" \
    -o "$WORK/test_v4_entry"

"$WORK/test_v4_entry"
