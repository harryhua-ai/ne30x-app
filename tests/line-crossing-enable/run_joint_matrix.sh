#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HOST_REPO=${HOST_REPO:-/Users/harryhua/Documents/GitHub/ne301}
HOST_SHA=dc0948c1e12e954612fbfa9769434bf01e449c3c
APP_SHA=${APP_SHA:-$(git -C "$ROOT" rev-parse HEAD)}
APP_TREE_SHA=$(git -C "$ROOT" rev-parse "$APP_SHA^{tree}")
HOST_SNAPSHOT="${TMPDIR:-/tmp}/ne30x-app-issue30-host-$HOST_SHA"
APP_DIR="$ROOT/apps/line-crossing"
APP_TESTS="$ROOT/tests/line-crossing-app"
MATRIX_CC=${CC:-cc}

if [ "$(git -C "$ROOT" rev-parse HEAD)" != "$APP_SHA" ]; then
    echo "FAIL: APP_SHA must match the checked out HEAD" >&2
    exit 1
fi
if ! git -C "$ROOT" diff --quiet || ! git -C "$ROOT" diff --cached --quiet; then
    echo "FAIL: source-pinned matrix requires a clean App worktree" >&2
    exit 1
fi
if [ "$(git -C "$HOST_REPO" rev-parse "$HOST_SHA^{commit}")" != "$HOST_SHA" ]; then
    echo "FAIL: exact Host source commit is unavailable" >&2
    exit 1
fi

mkdir -p "$HOST_SNAPSHOT"
if [ -f "$HOST_SNAPSHOT/.source-sha" ]; then
    if [ "$(cat "$HOST_SNAPSHOT/.source-sha")" != "$HOST_SHA" ]; then
        echo "FAIL: Host snapshot marker does not match the pinned SHA" >&2
        exit 1
    fi
else
    git -C "$HOST_REPO" archive "$HOST_SHA" | tar -x -C "$HOST_SNAPSHOT"
    printf '%s\n' "$HOST_SHA" > "$HOST_SNAPSHOT/.source-sha"
fi

printf 'HOST_SHA=%s\n' "$HOST_SHA"
printf 'APP_SHA=%s\n' "$APP_SHA"
printf 'APP_TREE_SHA=%s\n' "$APP_TREE_SHA"
printf 'HOST_SNAPSHOT=%s\n' "$HOST_SNAPSHOT"

make -C "$HOST_SNAPSHOT/tests/app_native_vnext" test
make -C "$HOST_SNAPSHOT/tests/app_host_session" test

RAISE_SOURCE_HITS=$(rg -n 'app_native_vnext_floor_raise[[:space:]]*\(' \
    "$HOST_SNAPSHOT" --glob '*.c' --glob '!**/tests/**' | wc -l | tr -d ' ')
if [ "$RAISE_SOURCE_HITS" != "1" ]; then
    echo "FAIL: Host floor raise production call-site shape changed; review the matrix" >&2
    exit 1
fi
printf 'HOST_FLOOR_RAISE_PRODUCTION_CALLS=0 (definition only)\n'

HOST_BUILD_OBJECTS=()
OBJECT_SUFFIX='*.o'
for object in "$HOST_SNAPSHOT"/tests/app_native_vnext/build/$OBJECT_SUFFIX; do
    [ -f "$object" ] && HOST_BUILD_OBJECTS+=("$object")
done

MATRIX_CFLAGS=(
    -std=c11
    -O1
    -g
    -Wall
    -Wextra
    -Werror
    "-I$HOST_SNAPSHOT/tests/sign_spike/shim"
    "-I$HOST_SNAPSHOT/tests/storage_gate/shim"
    "-I$HOST_SNAPSHOT/tests/app_installer"
    "-I$HOST_SNAPSHOT/tests/app_admission"
    "-I$HOST_SNAPSHOT/tests/sign_spike"
    "-I$HOST_SNAPSHOT/Custom/Services/AppHost"
    "-I$HOST_SNAPSHOT/Custom/Common/Inc"
    "-I$HOST_SNAPSHOT/Custom/Common/Utils"
    "-I$HOST_SNAPSHOT/Custom/Common/Lib"
    "-I$HOST_SNAPSHOT/Custom/Common/Lib/MbedTLS/include"
    "-I$HOST_SNAPSHOT/Custom/Common/Lib/MbedTLS/configs"
    "-I$HOST_SNAPSHOT/tests/app_native_vnext/build"
    "-I$APP_DIR/include"
    "-I$APP_DIR/app"
    "-I$APP_TESTS"
    '-DMBEDTLS_CONFIG_FILE="host_user_config.h"'
    -DMBEDTLS_ALLOW_PRIVATE_ACCESS
)

"$MATRIX_CC" "${MATRIX_CFLAGS[@]}" \
    "$ROOT/tests/line-crossing-enable/test_cross_owner_matrix.c" \
    "$APP_TESTS/host_stub.c" \
    "$APP_DIR/app/lc_app_entry_v4.c" \
    "$APP_DIR/app/lc_bus.c" \
    "$APP_DIR/app/lc_bus_config.c" \
    "$APP_DIR/app/lc_stateblob.c" \
    "$APP_DIR/app/lc_ctrl.c" \
    "$APP_DIR/app/lc_cfgcodec.c" \
    "$APP_DIR/app/lc_json.c" \
    "$APP_DIR/app/lc_arena.c" \
    "$APP_DIR/src/lc_tracker.c" \
    "$APP_DIR/src/lc_line_cross.c" \
    "$HOST_SNAPSHOT/Custom/Services/AppHost/app_host_control.c" \
    "$HOST_SNAPSHOT/tests/app_native_vnext/app_installer.o" \
    "$HOST_SNAPSHOT/tests/app_native_vnext/app_state_store.o" \
    "$HOST_SNAPSHOT/tests/app_native_vnext/app_admission.o" \
    "$HOST_SNAPSHOT/tests/app_native_vnext/app_trust_anchor.o" \
    "$HOST_SNAPSHOT/tests/app_native_vnext/generic_math.o" \
    "${HOST_BUILD_OBJECTS[@]}" \
    -o "$HOST_SNAPSHOT/tests/app_native_vnext/test_cross_owner_matrix"

"$HOST_SNAPSHOT/tests/app_native_vnext/test_cross_owner_matrix"
bash "$ROOT/tests/line-crossing-enable/run_tests.sh"
printf 'MATRIX_TESTS=PASS; FULL_AC4_PRODUCTION_GATE=NOT_RUN\n'
