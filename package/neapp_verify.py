#!/usr/bin/env python3
"""neapp_verify — offline verifier for signed .neapp v1 packages.

Consumes the same frozen v1 semantics as the packer via
package/neapp_format.py, in the normative order of the integrated P2 spec
(docs/app-package-protocol-v1.md §2.3 安全检查顺序, §7.1 判定顺序):

  1. bounded container structure (magic, lengths, caps, full consumption)
  2. strict-DER signature structural decode
  3. 160B manifest unique-encoding decode
  4. local trust mapping (publisher_id -> SHA-256(SPKI DER)); the package
     never self-trusts through any key material it carries
  5. ECDSA P-256 / SHA-256 verification over the exact TBS
  6. signed-content cross-checks (native header, digests, CRC, entry)
  7. board / PSRAM / ABI / capability / resource policy

Failure classes are the offline subset of the §7 taxonomy:
BAD_PACKAGE, SIGNATURE_INVALID, PUBLISHER_UNTRUSTED, TARGET_INCOMPATIBLE,
ABI_INCOMPATIBLE, RESOURCE_LIMIT.

The trust store JSON supplies the trusted publisher public keys from LOCAL
configuration (the offline stand-in for the Host-built-in trust anchor);
see tests/package/ for generated examples.

BOUNDARY: a PASS here is offline packaging-layer evidence only.  It does
NOT mean the package was installed on a device, executed, or that power-
fail recovery behaved correctly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import neapp_format as fmt  # noqa: E402

EXPECTED_RESULTS = ("PASS",) + tuple(cls.code for cls in fmt.ERROR_CLASSES)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--package", required=True, type=Path, help=".neapp package path")
    parser.add_argument("--trust", required=True, type=Path, help="trust store JSON")
    parser.add_argument("--policy", type=Path, default=None,
                        help="optional device-policy JSON overrides (board/ABI/region)")
    parser.add_argument("--expect", choices=EXPECTED_RESULTS, default=None,
                        help="assert this exact verification result (test harness mode)")
    parser.add_argument("--compact", action="store_true", help="one-line JSON output")
    args = parser.parse_args()

    try:
        data = args.package.read_bytes()
        trust = fmt.load_trust_store(args.trust)
        policy_data = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
        policy = fmt.DevicePolicy.from_json(policy_data)
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    report, err = fmt.verify_package(data, trust, policy)

    if report is not None:
        payload = report
        actual = "PASS"
        exit_code = 0
    else:
        actual = err.code
        payload = {
            "result": actual,
            "package_sha256": fmt.sha256_hex(data),
            "package_len": len(data),
            "detail": err.detail,
            "boundary": "offline verification only; no device install/execution claim",
        }
        exit_code = 1

    print(json.dumps(payload, sort_keys=True,
                     indent=None if args.compact else 2))

    if args.expect is not None:
        if actual != args.expect:
            print(f"FAIL: expected {args.expect}, got {actual} ({args.package})",
                  file=sys.stderr)
            return 1
        print(f"EXPECTED RESULT MATCH: {actual} — {args.package}", file=sys.stderr)
        return 0

    if exit_code != 0:
        print(f"REJECTED: {actual} — {args.package}", file=sys.stderr)
    else:
        print(f"VERIFIED: {actual} — {args.package}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
