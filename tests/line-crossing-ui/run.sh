#!/bin/sh
set -eu
TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$TEST_DIR/../.." && pwd)
cd "$TEST_DIR"
pnpm install --offline --frozen-lockfile --ignore-scripts
npm --prefix browser-runner ci --offline --ignore-scripts
node browser-runner/build.mjs
node --test contract.test.mjs browser.test.mjs
sh "$REPO_ROOT/tests/line-crossing-runtime/run.sh"
