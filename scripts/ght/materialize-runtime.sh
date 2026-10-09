#!/bin/sh
# Thin downstream runtime materializer for the ne30x-app ght integration
# (Harry Dev downstream thin-caller model, harry-dev docs/adoption.md): resolves the repository's ACTIVATED github-task runtime identity
# from its own refs/ght runtime namespace, materializes that immutable,
# content-addressed capsule, and prints the materialized runtime directory
# (the parent of scripts/ght.py) for delegation.
#
# The Harry Dev runtime is never copied into this repository: it is
# published into this repository itself as an immutable capsule
# (`refs/ght/runtime/<payload-digest>` holding runtime.zip + MANIFEST.json,
# written by `ght sync-runtime` from the installed distribution). This
# script owns NO runtime semantics; it only proves content identity before
# materializing, exactly like the canonical completion adapter:
#   - the capsule commit must not change identity mid-read (private temp
#     ref, exact observed object SHA), and
#   - the payload must be self-consistent: sha256(runtime.zip) MUST equal
#     MANIFEST.json's `digest`, with a coherent release identity and exact
#     source SHA.
# With an explicit pin (GHT_RUNTIME_REF, a 64-hex payload digest) the
# capsule under refs/ght/runtime/<pin> must additionally self-report that
# same digest — a floating/latest value is refused. Any divergence fails
# closed with diagnostics; there is deliberately no retry, fallback, or
# payload mending.
#
# Usage:
#   dir=$(scripts/ght/materialize-runtime.sh)
#
# Environment:
#   GHT_RUNTIME_REF   explicit project pin (64-hex payload digest); used
#                     ONLY as an explicit alternative to the activated
#                     `refs/ght/runtime/current` identity — never a guess
#   GHT_RUNTIME_DIR   test seam: skip materialization, echo this directory
#   GHT_MATERIALIZE_REMOTE   git remote to read the capsule from
#                            (default: origin)
set -eu

die() {
    echo "ght-materialize-runtime: $1" >&2
    exit 1
}

if [ -n "${GHT_RUNTIME_DIR:-}" ]; then
    [ -d "$GHT_RUNTIME_DIR" ] || die "GHT_RUNTIME_DIR '$GHT_RUNTIME_DIR' is not a directory"
    [ -f "$GHT_RUNTIME_DIR/scripts/ght.py" ] || die "GHT_RUNTIME_DIR '$GHT_RUNTIME_DIR' carries no scripts/ght.py"
    echo "$GHT_RUNTIME_DIR"
    exit 0
fi

remote=${GHT_MATERIALIZE_REMOTE:-origin}
ref_name="refs/ght/runtime/current"
if [ -n "${GHT_RUNTIME_REF:-}" ]; then
    case "${GHT_RUNTIME_REF}" in
        [0-9a-f]*) ref_name="refs/ght/runtime/${GHT_RUNTIME_REF}" ;;
        *) die "GHT_RUNTIME_REF must be a 64-hex payload digest, got '${GHT_RUNTIME_REF}'" ;;
    esac
fi

# Read the exact capsule object identity BEFORE fetching: capsules are
# create-only immutable, so any divergence is an interleaved-corruption
# signal and fails closed. Private temp ref only — never the shared
# FETCH_HEAD other automation races on.
want=$(git ls-remote "$remote" "$ref_name" | cut -f1)
[ -n "$want" ] || die "runtime capsule ref $ref_name is absent from this repository; materialize the activated distribution with 'ght sync-runtime' and retry"
capsule_ref="refs/ght/tmp/materialize-$$"
cleanup() { git update-ref -d "$capsule_ref" 2>/dev/null || true; }
trap cleanup EXIT HUP INT TERM
git fetch --force "$remote" "+$ref_name:$capsule_ref" 1>&2
got=$(git rev-parse "${capsule_ref}^{commit}")
[ "$got" = "$want" ] || die "runtime capsule $ref_name changed identity mid-read ($want -> $got); fail closed"

runtime_tmp=$(mktemp -d)
git show "$capsule_ref:runtime.zip" > "$runtime_tmp/runtime.zip"
git show "$capsule_ref:MANIFEST.json" > "$runtime_tmp/MANIFEST.json"

# Verify BOTH the payload digest and the capsule manifest identity before
# materializing anything; any divergence fails closed.
pin=$(python3 - "$runtime_tmp/runtime.zip" "$runtime_tmp/MANIFEST.json" ${GHT_RUNTIME_REF:+"$GHT_RUNTIME_REF"} <<'PYEOF'
import hashlib, json, re, sys
payload_digest = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
try:
    manifest = json.load(open(sys.argv[2]))
except ValueError:
    raise SystemExit(f"ght-materialize-runtime: capsule manifest is not parseable; fail closed")
pin = manifest.get("digest")
if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
    raise SystemExit(f"ght-materialize-runtime: capsule manifest carries no 64-hex digest; fail closed")
if payload_digest != pin:
    raise SystemExit(f"ght-materialize-runtime: capsule payload digest {payload_digest[:12]} "
                     f"diverges from manifest digest {pin[:12]}; fail closed")
if len(sys.argv) > 3 and sys.argv[3] != pin:
    raise SystemExit(f"ght-materialize-runtime: capsule self-reports digest {pin[:12]} "
                     f"diverging from pinned identity {sys.argv[3][:12]}; fail closed")
if not isinstance(manifest.get("release"), str) \
        or not re.fullmatch(r"v\d+(?:\.\d+)*", manifest["release"].strip()):
    raise SystemExit(f"ght-materialize-runtime: capsule manifest carries no coherent Harry Dev "
                     f"release identity; fail closed")
if not isinstance(manifest.get("source_sha"), str) \
        or not re.fullmatch(r"[0-9a-f]{7,40}", manifest.get("source_sha", "").strip()):
    # Repo-local relaxation vs the canonical adapter: the runtime stamps
    # capsule source_sha with `git rev-parse --short` (github_task/cli.py
    # release-stamping), so released capsules carry short SHAs by design.
    raise SystemExit(f"ght-materialize-runtime: capsule manifest carries no exact source SHA; "
                     f"fail closed")
print(pin)
PYEOF
) || die "capsule content verification failed; nothing materialized"

unzip -q "$runtime_tmp/runtime.zip" -d "$runtime_tmp/runtime"
runtime_dir=$(find "$runtime_tmp/runtime" -maxdepth 2 -name scripts -type d \
    | head -1 | xargs dirname)
[ -f "${runtime_dir}/scripts/ght.py" ] \
    || die "materialized capsule does not carry scripts/ght.py; fail closed"
# The capsule packs scripts/ght.py 0644 (only the .sh glues carry the exec
# bit), while the canonical glues' `exec "$GHT_*_GHT_BIN"` delegation paths
# direct-exec the entrypoint; restore the bit after verification — payload
# content stays digest-bound, this only normalizes the file mode.
chmod 755 "${runtime_dir}/scripts/ght.py"
echo "ght-materialize-runtime: materialized runtime capsule $pin (ref $ref_name @ $want)" >&2
echo "$runtime_dir"
