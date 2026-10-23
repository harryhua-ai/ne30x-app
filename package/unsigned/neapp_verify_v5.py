from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package" / "unsigned"))
sys.path.insert(0, str(ROOT / "package" / "vnext"))

import neapp_v4_format as v4
import neapp_v5_format as v5


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--host-policy", type=Path, default=None)
    parser.add_argument("--no-host-admission", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    policy = None
    if args.host_policy is not None:
        try:
            policy = v4.DevicePolicyV4.from_json(
                json.loads(args.host_policy.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError) as error:
            print(json.dumps({"result": "INPUT_ERROR", "detail": str(error)}, sort_keys=True,
                             indent=None if args.compact else 2))
            return 1
    try:
        report, error = v5.verify_package_v5(
            args.package.read_bytes(),
            policy=policy,
            host_admission=not args.no_host_admission,
        )
    except OSError as error:
        print(json.dumps({"result": "INPUT_ERROR", "detail": str(error)}, sort_keys=True,
                         indent=None if args.compact else 2))
        return 1
    if error is not None:
        print(json.dumps({"result": error.code, "detail": error.detail}, sort_keys=True,
                         indent=None if args.compact else 2))
        return 1
    print(json.dumps(report, sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
