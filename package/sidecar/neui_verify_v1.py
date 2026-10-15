#!/usr/bin/env python3
"""neui_verify_v1 — offline verifier for signed NEUI UI-Sidecar v1 bundles.

Consumes the frozen Sidecar v1 semantics via
package/sidecar/neui_sidecar_format.py, in the normative order:

  1. bounded container structure (NEUI v1 magic 4e45554901000000,
     manifest_len 128..16384, asset_payload_len 1..2097152, truncation,
     DER window with the tail fully consumed; unknown container versions
     reject — native .neapp v1/v2/v3 packages are never parsed)
  2. strict DER structural decode (full consumption)
  3. manifest strict decode: v3 identifier rules for publisher_id/app_id,
     sidecar_version_major >= 1, file_count 1..64, host_ui_abi == 1,
     reserved == 0, exact record framing, canonical relative POSIX paths,
     strict ascending raw-ASCII order, no duplicates or ASCII-case-fold
     collisions, exactly one root index.html
  4. local trust mapping (publisher_id -> SHA-256(SPKI DER)); the bundle
     never self-trusts through any key material it carries
  5. ECDSA P-256 / SHA-256 verification over the exact raw TBS
  6. signed-content cross-checks: asset_payload_len == sum(record
     file_len), per-asset SHA-256 in record order, and — when
     --native-package is given — the native binding (native_tbs_sha256,
     publisher_id, app_id, publisher_key_sha256 must all match the native
     .neapp v3 package).  With --native-trust the native must first PASS
     full offline v3 verification and the report marks the binding
     native_binding_trusted=true; without it the native bytes are only
     structurally parsed and identity-compared — reported as
     native_binding_trusted=false (an untrusted byte-only cross-check,
     never presented as verified native admission)

Failure classes: BAD_PACKAGE, SIGNATURE_INVALID, PUBLISHER_UNTRUSTED.

The trust store JSON supplies trusted publisher public keys from LOCAL
configuration; the native package/identity facts are LOCAL inputs too.
A PASS proves offline bundle structure/signature only — NOT NE301 Host
admission or install, LittleFS free space, RAM fit, a dual-artifact
transaction, camera H264, browser trusted loading, or User acceptance.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import neapp_format as fmt
import neui_sidecar_format as sc

EXPECTED_RESULTS = ("PASS",) + tuple(cls.code for cls in sc.ERROR_CLASSES)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bundle", required=True, type=Path, help=".neui bundle path")
    parser.add_argument("--trust", required=True, type=Path, help="trust store JSON")
    parser.add_argument("--native-package", type=Path, default=None,
                        help="optional .neapp v3 package for native-binding cross-check "
                             "(native_tbs_sha256 + publisher_id + app_id + key fingerprint)")
    parser.add_argument("--native-trust", type=Path, default=None,
                        help="optional trust store JSON; given together with --native-package, "
                             "the native must first PASS full offline v3 verification and the "
                             "binding is reported native_binding_trusted=true; omitted, the "
                             "cross-check is an untrusted byte-only comparison reported "
                             "native_binding_trusted=false")
    parser.add_argument("--expect", choices=EXPECTED_RESULTS, default=None,
                        help="assert this exact verification result (test harness mode)")
    parser.add_argument("--compact", action="store_true", help="one-line JSON output")
    args = parser.parse_args()

    try:
        data = args.bundle.read_bytes()
        trust = fmt.load_trust_store(args.trust)
        native_package = args.native_package.read_bytes() if args.native_package else None
        native_trust = fmt.load_trust_store(args.native_trust) if args.native_trust else None
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    report, err = sc.verify_bundle(data, trust, native_package, native_trust)

    if report is not None:
        payload = report
        actual = "PASS"
        exit_code = 0
    else:
        actual = err.code
        payload = {
            "result": actual,
            "bundle_sha256": fmt.sha256_hex(data),
            "bundle_len": len(data),
            "detail": err.detail,
            "boundary": "offline verification only; no NE301 Host admission/install claim",
        }
        exit_code = 1

    print(json.dumps(payload, sort_keys=True,
                     indent=None if args.compact else 2))

    if args.expect is not None:
        if actual != args.expect:
            print(f"FAIL: expected {args.expect}, got {actual} ({args.bundle})",
                  file=sys.stderr)
            return 1
        print(f"EXPECTED RESULT MATCH: {actual} — {args.bundle}", file=sys.stderr)
        return 0

    if exit_code != 0:
        print(f"REJECTED: {actual} — {args.bundle}", file=sys.stderr)
    else:
        print(f"VERIFIED: {actual} — {args.bundle}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
