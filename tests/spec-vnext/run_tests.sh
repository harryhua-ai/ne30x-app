#!/bin/sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
exec python3 "$ROOT/tests/spec-vnext/run_all_tests.py"
