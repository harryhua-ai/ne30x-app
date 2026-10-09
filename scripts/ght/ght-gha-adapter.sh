#!/bin/sh
# Thin downstream caller for the Mechanical Reconciler (#63 AC21).
#
# A downstream business repository keeps ONLY this adapter (plus its own
# repo-local workflow invoking it). The Harry Dev runtime is never copied
# into the downstream repo and never fetched cross-repo: it is published
# into the TARGET repo itself as immutable, content-addressed capsules —
# `refs/ght/runtime/<digest>`, written by `ght sync-runtime` from the
# installed, stamped Harry Dev distribution — and this adapter materializes
# the capsule THE ATTEMPT IS BOUND TO (every new attempt durably records
# the activated runtime identity in its claim lineage at claim time), so a
# later project pin upgrade or rollback never moves the runtime under an
# existing ACTIVE attempt or its post-merge completion. No PAT, no
# floating versions, no cross-repo access: a private downstream repo and a
# public one consume the identical capsule from their own repository.
#
# Required environment (set by the repo-local workflow):
#   ISSUE, PR         the merged Candidate's issue and PR numbers (or $1 $2)
#   GH_TOKEN          the workflow's built-in token (downstream repo scope)
# Optional:
#   GHT_RUNTIME_REF   explicit project pin fallback — used ONLY when the
#                     attempt carries no runtime binding (attempts that
#                     predate the binding); otherwise the attempt's own
#                     binding wins. A floating/latest value is refused.
#   GHT_RUNTIME_DIR   test seam: use a pre-fetched runtime dir instead of
#                     materializing the pinned capsule
set -eu

die() {
    echo "ght-gha-adapter: $1" >&2
    exit 1
}

require_digits() {
    case "$1" in
        ''|*[!0-9]*) die "expected a numeric $2, got '$1'" ;;
    esac
}

issue=${1:-${ISSUE:-}}
pr=${2:-${PR:-}}
require_digits "$issue" "issue"
require_digits "$pr" "pr"

runtime_digest=""
claim_ref=""
capsule_ref=""
# R4-2: every claim-lineage / capsule read goes through a PRIVATE
# temporary ref (fetch refspec straight into refs/ght/tmp/…), never
# through the shared FETCH_HEAD other automation races on; the refs are
# dropped again on every exit path, including before the final exec
# (an exec'd replacement would never run the EXIT trap).
cleanup_temp_refs() {
    if [ -n "$claim_ref" ]; then git update-ref -d "$claim_ref" 2>/dev/null || true; fi
    if [ -n "$capsule_ref" ]; then git update-ref -d "$capsule_ref" 2>/dev/null || true; fi
}
trap cleanup_temp_refs EXIT HUP INT TERM

if [ -z "${GHT_RUNTIME_DIR:-}" ]; then
    # 1) The attempt's own durable runtime binding (claim lineage). A
    # missing/unbound lineage falls through to the explicit project pin.
    claim_ref="refs/ght/tmp/claim-$issue-$$"
    git fetch --force origin "+refs/ght/claims/$issue:$claim_ref" 1>&2 || true
    runtime_digest=$(python3 - "$issue" "$claim_ref" <<'PYEOF'
import json, subprocess, sys
issue, claim_ref = sys.argv[1], sys.argv[2]
shown = subprocess.run(["git", "show", f"{claim_ref}:CLAIM.json"],
                       capture_output=True, text=True)
if shown.returncode:
    print("ght-gha-adapter: no claim lineage to resolve a binding from",
          file=sys.stderr)
    raise SystemExit(3)
try:
    claim = json.loads(shown.stdout)
except ValueError:
    print("ght-gha-adapter: claim record is not parseable", file=sys.stderr)
    raise SystemExit(3)
digest = (claim.get("runtime") or {}).get("digest")
if digest:
    print(digest)
else:
    print(f"ght-gha-adapter: attempt #{sys.argv[1]} carries no runtime binding",
          file=sys.stderr)
raise SystemExit(0 if digest else 3)
PYEOF
) || runtime_digest=""
    if [ -z "$runtime_digest" ]; then
        # 2) Explicit project pin fallback for unbound (legacy) attempts.
        [ -n "${GHT_RUNTIME_REF:-}" ] \
            || die "attempt #$issue carries no runtime binding and no GHT_RUNTIME_REF pin fallback; refusing to guess the runtime"
        case "${GHT_RUNTIME_REF}" in
            [0-9a-f]*) runtime_digest=${GHT_RUNTIME_REF} ;;
            *) die "GHT_RUNTIME_REF must be the content digest of a runtime capsule, got '${GHT_RUNTIME_REF}'" ;;
        esac
    fi
    case "$runtime_digest" in
        [0-9a-f]*) ;;
        *) die "runtime digest '$runtime_digest' is not a content digest" ;;
    esac

    runtime_tmp=$(mktemp -d)
    # Fetch the bound capsule from THIS repository (the runner's own
    # checkout scope — identical for private and public downstream repos)
    # into a private temp ref, pinned to the exact object identity observed
    # before the fetch: capsules are create-only immutable, so any
    # divergence is an interleaved-corruption signal and fails closed.
    capsule_ref="refs/ght/tmp/capsule-$issue-$$"
    want=$(git ls-remote origin "refs/ght/runtime/$runtime_digest" | cut -f1)
    [ -n "$want" ] || die "runtime capsule $runtime_digest is absent from this repository; materialize the bound distribution with 'ght sync-runtime' and retry"
    git fetch --force origin "+refs/ght/runtime/$runtime_digest:$capsule_ref" 1>&2
    got=$(git rev-parse "${capsule_ref}^{commit}")
    [ "$got" = "$want" ] || die "runtime capsule $runtime_digest changed identity mid-read ($want -> $got); fail closed"
    git show "$capsule_ref:runtime.zip" > "$runtime_tmp/runtime.zip"
    git show "$capsule_ref:MANIFEST.json" > "$runtime_tmp/MANIFEST.json"
    # Verify BOTH the payload digest and the capsule manifest identity
    # before materializing anything; any divergence fails closed.
    python3 - "$runtime_tmp/runtime.zip" "$runtime_tmp/MANIFEST.json" \
        "$runtime_digest" <<'PYEOF' 1>&2
import hashlib, json, re, sys
payload_digest = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
pin = sys.argv[3]
try:
    manifest = json.load(open(sys.argv[2]))
except ValueError:
    raise SystemExit(f"ght-gha-adapter: capsule manifest is not parseable; fail closed")
if payload_digest != pin:
    raise SystemExit(f"ght-gha-adapter: capsule payload digest {payload_digest[:12]} "
                     f"diverges from pinned identity {pin[:12]}; fail closed")
if manifest.get("digest") != pin:
    raise SystemExit(f"ght-gha-adapter: capsule manifest digest {str(manifest.get('digest'))[:12]} "
                     f"diverges from pinned identity {pin[:12]}; fail closed")
if not isinstance(manifest.get("release"), str) \
        or not re.fullmatch(r"v\d+(?:\.\d+)*", manifest["release"].strip()):
    raise SystemExit(f"ght-gha-adapter: capsule manifest carries no coherent Harry Dev "
                     f"release identity; fail closed")
if not isinstance(manifest.get("source_sha"), str) \
        or not re.fullmatch(r"[0-9a-f]{7,40}", manifest.get("source_sha", "").strip()):
    # Repo-local relaxation vs the canonical adapter: the runtime stamps
    # capsule source_sha with `git rev-parse --short` (github_task/cli.py
    # release-stamping), so released capsules carry short SHAs by design —
    # the upstream 40-hex check refuses the runtime's own v1.1.1 capsule.
    raise SystemExit(f"ght-gha-adapter: capsule manifest carries no exact source SHA; "
                     f"fail closed")
PYEOF
    unzip -q "$runtime_tmp/runtime.zip" -d "$runtime_tmp/runtime"
    GHT_RUNTIME_DIR=$(find "$runtime_tmp/runtime" -maxdepth 2 -name scripts -type d \
        | head -1 | xargs dirname)
    echo "ght-gha-adapter: materialized runtime capsule $runtime_digest (attempt #$issue binding)" >&2
fi

[ -f "${GHT_RUNTIME_DIR}/scripts/ght-gha-complete.sh" ] \
    || die "pinned runtime at ${GHT_RUNTIME_DIR} does not carry the canonical completion glue"

# Drop the private temp refs BEFORE the exec: the exec'd replacement never
# runs this shell's EXIT trap, and the glue's own git operations must not
# inherit our temporary refs as residue.
cleanup_temp_refs
trap - EXIT HUP INT TERM

# Delegate entirely to the canonical completion glue of the bound runtime:
# every durable predicate is verified by ght itself; this adapter owns no
# completion semantics and fails closed with its diagnostics.
exec "${GHT_RUNTIME_DIR}/scripts/ght-gha-complete.sh" complete "$issue" "$pr"
