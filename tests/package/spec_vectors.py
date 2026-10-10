#!/usr/bin/env python3
"""spec_vectors — reconstruct and verify the frozen P2 spec §2.5 vectors.

The integrated spec docs/app-package-protocol-v1.md §2.5 publishes a set of
byte-exact golden/negative packages: full HEX blobs, complete DER strings,
per-index TBS modification recipes, and the SHA-256 of every resulting
file.  This module rebuilds each of them EXACTLY as published, hard-asserts
every published SHA-256 (proving byte-exact reconstruction), then runs the
real offline verifier CLI (package/neapp_verify.py) and requires the
protocol-expected result class for every vector.

Vectors whose bytes the spec does not publish (only a SHA-256 in the
"已运行的有限离线拒绝/幂等证据" table) cannot be reconstructed byte-exact;
they are covered by documented locally-generated equivalents in
tests/package/generated_cases.py — never by inventing bytes.

Exit code 0 only if every hash assertion and every expected result matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERIFY = REPO / "package" / "neapp_verify.py"

# ---- spec §2.5 published material (verbatim) ------------------------------

GOLDEN_HEX = (
    "4e45415050010000a0000000240000004e4d4631746573742d7075626c697368"
    "6572000068656c6c6f2d61707000000000000000000000000000000000000000"
    "0000000001000000000000001030000040000000000001000300000004000000"
    "2400000004000000000000000000e09337d3abca3d54a2ec9cb14f5602234777"
    "56e74ecd319bc7f9af8e304d57eb66ca5cd252fb0ce8932436faf8ccd1040981"
    "b89ee4ad6b9fe9e2a2b7e71aacb27cd34e45413120000100000001000000e093"
    "04000000000000000000000039348ede0020704730460221009b9d250faaea7a"
    "a92f6ccd3515137de5012f9150f0088eadee8770dc23b3a133022100ba360d6c"
    "ffb44219fb9b36b39c82665748577ac016c9e8e4648b1cdd54910038"
)
SPEC_SPKI_HEX = (
    "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e1"
    "2c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe"
    "1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
LOW_S_DER_HEX = (
    "30450221009b9d250faaea7aa92f6ccd3515137de5012f9150f0088eadee8770d"
    "c23b3a133022045c9f292004bbde70464c94c637d99a8748f7fed904db5a08f2e"
    "ade5a7d22519"
)
DER70_HEX = (
    "304402201b807dc9f67b49746986ad1cf6490fcd3030c10c419329dd58bac4cb8"
    "4a78f740220049be7b978bdf57e0cf37df5eef74ebf6abf485ec05b2f5d76b58a"
    "6aa6aad400"
)
RESERVED0_DER_HEX = (
    "304502207025c9259b84cf28951c66cf4ec8282d7b8db7823d6e107e695fc7257"
    "ed688de022100ff36e6990fb2f43b8229cfa7888f83b4d847315ab06b3afcf661"
    "a04d02fabee8"
)

TBS_LEN = 212  # 16 + 160 + 36, the golden signed region (§2.5)

# The seven fixed per-index negatives (spec §2.5, 2026-10-09 block):
# (name, byte-set ops as (start, end, hex) TBS slices, update_native_digest,
#  DER hex, expected TBS sha256, expected package sha256, expected class)
FIXED_NEGATIVES = [
    ("manifest_uppercase_app_id", [(36, 37, "48")], False,
     "304402207e97f10fa005f03588b357a7dea06378c4f9b863ed6f5ec591d0511b9dffd58"
     "2022047680cc8ca63bf36f98334ce7d85de9635e96b18fc870e38579a5544e56b157a",
     "48a888f0530deae312d4e937c6bc245bc47eff012d4c3aab175f2b1eaafe5f7f",
     "bee6d6132c5cd50e32c6b504ec908634d3eb2fb3df844e10021139cc813e4211",
     "BAD_PACKAGE"),
    ("manifest_reserved_nonzero", [(74, 75, "01")], False,
     "304502204866bb6bd2e03e4124cd144345fd596995f156e3c58d469c4f76bb3f474b2b1"
     "6022100b350242de5f9469ce268fd466cb48d78303608309316503b314e464e38192312",
     "4004fce0ca7068f31e986c931f908feeaa82014d3d1b6b1dd76f57e853fef56d",
     "32529b608cc1371a4748b1458a12e5dec951f2c6ec258b5ec24f97ccb3ceff12",
     "BAD_PACKAGE"),
    ("wrong_board_signed", [(76, 77, "11")], False,
     "3045022100e8898839a6f58455e56802b94e57f2c9ed87427ac94d28dcead5be3a89f10"
     "a35022069996233cc83a838d005e343a034cba920e6e22ef78e1116277bfc465381ad4b",
     "b8a6feff4dad64c6a78b3b4073c7a07622f5223b8d5dae21b2edcb1ad1619097",
     "a9e82949c0b796950d98f40164256651f64d45c794ceed2e5d2cdd883af6a50e",
     "TARGET_INCOMPATIBLE"),
    ("untrusted_key_fingerprint", [(144, 145, "5d")], False,
     "304502205adfb37c741caea9c35aded725c58f741f76b6e89f44fcf3ac02e988fb640a4"
     "2022100fb012d1db335862355c19db1bd6097973559a775a3e8cf6e581c21536f86954b",
     "23cf61624fa63f8178331032ed2383aff485e1058201d60ba0a2e005972f2262",
     "45590d2517ca13e951a2f9c6f4bb209c59dc7cf81d209ff103b98b77c423df2b",
     "PUBLISHER_UNTRUSTED"),
    ("native_header_size_33", [(180, 182, "2100")], True,
     "30450220148724ab85236e5476004fa809296e9356ee6baababb3f1efd3adfae4580bb1"
     "5022100947f27288b193cb96690f74e6bba322eb9f0db023395c1d252b13564dc2da461",
     "48ac4096ef8184e7b6334ab6d1c433575cdc63ad02dcba565c81a4f8b20a3c21",
     "97b2f926b962a34d398799c3d21bc70927b12abd960f635805304bed664d2657",
     "BAD_PACKAGE"),
    ("native_entry_offset_oob", [(104, 108, "04000000"), (196, 200, "04000000")], True,
     "3045022100f975343a1dc0a299d7c025880eb6b75605dcf9c45c56213e355ca6a97011e"
     "af60220637ae638b2a29bd8f29b55f492c7ce891d7f10199eb12fa5b3d95279a9ca9932",
     "12568c925fe3df065f79a9a97cc93352333e726e2acd226d69f7a6760700fb65",
     "9b4d74a6f4ab72b56b1036abee60adfb73a823cfaa933e459a6dcae093beb370",
     "BAD_PACKAGE"),
    ("mismatched_manifest_native_len", [(96, 100, "25000000")], False,
     "3045022100ebf4f555a10986714ade5fac847c34d25aaefdf0b82a5d2a2914ea6214de1"
     "0e9022007395ef4160d093aaf4cf61981d0eb0b2e345e18e58abfcea8d932cd6ef09df1",
     "2d9c5ba0e8e0019396814d53215a0c53c9c8d69593a6f713f980314a1827e619",
     "f8cccc3cd59f09d266fd788320510ca550dba3c5355b717d42c71226241b2938",
     "BAD_PACKAGE"),
]

# Published SHA-256 anchors from the spec prose/tables
GOLDEN_SHA256 = "9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679"
TBS_SHA256 = "5035e6512c0c003490b228b9ae0dc6351166a04b0dc96a3ff053bb7fe348fe91"
SPKI_SHA256 = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
LOW_S_PKG_SHA256 = "99469a8303f91ab3c8f523ac2a2435dce2ee28ef7b73385d0a2fb3da16e36685"
DER70_PKG_SHA256 = "2fcbeb5b425ac1fa35c43a54c7178e0008b0fbad04dc13298cbaab8643f5d93d"
DER_TAIL_PKG_SHA256 = "ab8391274bad0fa8ec41c3c483a5840fd0a64ca0f6602a07bb723f4c08adc2d2"
RESERVED0_PKG_SHA256 = "585f5f61c9621947d62783095ffe2d8701745e520b8af161038c5c1e9891e480"
GOLDEN_PLUS1_SHA256 = "4ceeff8e9a0de2a840fe2529c871bf1eeba65e37bc34502f83b7113f19b86201"
RESERVED0_NATIVE_SHA256 = "246c57c25fc8da69559a8778ea466aac7e6d4c8789839e7b6e381bed5adae380"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_eq(actual, expected, what: str) -> None:
    if actual != expected:
        raise AssertionError(f"{what}: got {actual}, spec says {expected}")


def run_verifier(package: Path, trust: Path, expect: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(VERIFY), "--package", str(package), "--trust", str(trust),
         "--expect", expect, "--compact"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"verifier did not produce expected {expect} for {package.name}:\n"
            f"{proc.stdout}{proc.stderr}"
        )
    return json.loads(proc.stdout.strip().splitlines()[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="work directory for reconstructed vectors")
    args = parser.parse_args()

    vec_dir = args.out_dir / "vectors"
    vec_dir.mkdir(parents=True, exist_ok=True)

    # Local trust store for the spec's published NON-PRODUCTION test key
    # (P-256 scalar d=1; public and unsafe by design, §2.5).
    spki = bytes.fromhex(SPEC_SPKI_HEX)
    assert_eq(sha256(spki), SPKI_SHA256, "spec test SPKI sha256")
    trust_path = args.out_dir / "trust-spec.json"
    trust_path.write_text(json.dumps({
        "version": 1,
        "comment": "P2 spec §2.5 public non-production test key (d=1); NOT a production root",
        "publishers": {"test-publisher": {"spki_der_hex": SPEC_SPKI_HEX}},
    }, indent=2) + "\n", encoding="utf-8")

    results: list[dict] = []

    def record(name: str, spec_ref: str, expect: str, package: bytes,
               spec_sha: str | None, report: dict | None) -> None:
        results.append({
            "vector": name,
            "spec_reference": spec_ref,
            "expected": expect,
            "observed": (report or {}).get("result", expect),
            "package_sha256": sha256(package),
            "spec_published_sha256": spec_sha,
            "hash_matched_spec": spec_sha is None or sha256(package) == spec_sha,
            "content_identity_sha256": (report or {}).get("content_identity_sha256"),
        })

    # ---- golden.neapp (spec §2.5 HEX blob) ---------------------------------
    golden = bytes.fromhex(GOLDEN_HEX)
    assert_eq(len(golden), 284, "golden package length")
    assert_eq(sha256(golden), GOLDEN_SHA256, "golden package sha256")
    assert_eq(sha256(golden[:TBS_LEN]), TBS_SHA256, "golden TBS sha256")
    (vec_dir / "golden.neapp").write_bytes(golden)
    report = run_verifier(vec_dir / "golden.neapp", trust_path, "PASS")
    record("golden_accept", "§2.5 golden.neapp", "PASS", golden, GOLDEN_SHA256, report)

    # ---- low-S variant over the UNCHANGED golden TBS (§2.5 low-S block) ----
    low_s = golden[:TBS_LEN] + bytes.fromhex(LOW_S_DER_HEX)
    assert_eq(sha256(low_s), LOW_S_PKG_SHA256, "low-S package sha256")
    (vec_dir / "golden_low_s.neapp").write_bytes(low_s)
    report = run_verifier(vec_dir / "golden_low_s.neapp", trust_path, "PASS")
    assert_eq(report["content_identity_sha256"], TBS_SHA256,
              "low-S variant must share the golden content identity")
    record("golden_low_s_accept", "§2.5 low-S/high-S 对照 (s→n-s)", "PASS", low_s,
           LOW_S_PKG_SHA256, report)

    # ---- der_70byte_valid (§2.5 DER 尾随校验 block) --------------------------
    der70_pkg = golden[:TBS_LEN] + bytes.fromhex(DER70_HEX)
    assert_eq(sha256(der70_pkg), DER70_PKG_SHA256, "70B DER package sha256")
    (vec_dir / "der_70byte_valid.neapp").write_bytes(der70_pkg)
    record("der_70byte_valid_accept", "§2.5 der_70byte_valid.neapp", "PASS",
           der70_pkg, DER70_PKG_SHA256,
           run_verifier(vec_dir / "der_70byte_valid.neapp", trust_path, "PASS"))

    # ---- der_tail_within_72byte_limit (same 70B DER + one trailing 0xFF) ----
    der_tail_pkg = der70_pkg + b"\xff"
    assert_eq(sha256(der_tail_pkg), DER_TAIL_PKG_SHA256, "DER tail package sha256")
    (vec_dir / "der_tail_within_72byte_limit.neapp").write_bytes(der_tail_pkg)
    record("der_tail_within_72byte_limit", "§2.5 der_tail_within_72byte_limit.neapp",
           "BAD_PACKAGE", der_tail_pkg, DER_TAIL_PKG_SHA256,
           run_verifier(vec_dir / "der_tail_within_72byte_limit.neapp", trust_path, "BAD_PACKAGE"))

    # ---- reserved0 nonzero, digest fixed, re-signed (§2.5 prose recipe) -----
    tbs = bytearray(golden[:TBS_LEN])
    tbs[200] = 0x01  # native header reserved0 (package offset 200..203)
    native_sha = sha256(bytes(tbs[176:212]))
    assert_eq(native_sha, RESERVED0_NATIVE_SHA256, "reserved0 vector native sha256")
    tbs[112:144] = bytes.fromhex(native_sha)  # manifest native_file_sha256
    reserved0_pkg = bytes(tbs) + bytes.fromhex(RESERVED0_DER_HEX)
    assert_eq(sha256(reserved0_pkg), RESERVED0_PKG_SHA256, "reserved0 package sha256")
    (vec_dir / "native_reserved0_signed.neapp").write_bytes(reserved0_pkg)
    record("native_reserved0_signed_reject", "§2.5 reserved0 独立负例（正确签名仍须拒绝）",
           "BAD_PACKAGE", reserved0_pkg, RESERVED0_PKG_SHA256,
           run_verifier(vec_dir / "native_reserved0_signed.neapp", trust_path, "BAD_PACKAGE"))

    # ---- golden + 1 appended byte (72B→73B DER segment; §2.5 table) ---------
    # The published sha256 pins the appended byte to 0xFF.
    golden_plus1 = golden + b"\xff"
    assert_eq(sha256(golden_plus1), GOLDEN_PLUS1_SHA256, "golden+1B package sha256")
    (vec_dir / "golden_der_73byte.neapp").write_bytes(golden_plus1)
    record("golden_der_73byte_reject", "§2.5 72B DER 后追加 1 字节", "BAD_PACKAGE",
           golden_plus1, GOLDEN_PLUS1_SHA256,
           run_verifier(vec_dir / "golden_der_73byte.neapp", trust_path, "BAD_PACKAGE"))

    # ---- the seven fixed per-index negatives --------------------------------
    for name, ops, update_digest, der_hex, tbs_sha, pkg_sha, expect in FIXED_NEGATIVES:
        tbs = bytearray(golden[:TBS_LEN])
        for start, end, hexval in ops:
            tbs[start:end] = bytes.fromhex(hexval)
        if update_digest:
            tbs[112:144] = bytes.fromhex(sha256(bytes(tbs[176:212])))
        assert_eq(sha256(bytes(tbs)), tbs_sha, f"{name} TBS sha256")
        pkg = bytes(tbs) + bytes.fromhex(der_hex)
        assert_eq(sha256(pkg), pkg_sha, f"{name} package sha256")
        path = vec_dir / f"{name}.neapp"
        path.write_bytes(pkg)
        record(name, f"§2.5 固定负例 {name}", expect, pkg, pkg_sha,
               run_verifier(path, trust_path, expect))

    # ---- byte-unrecoverable spec rows: recorded for the mapping table -------
    results.append({
        "vector": "tampered_signed_content (equivalent generated locally)",
        "spec_reference": "§2.5 表：已签名内容被篡改 d415350f… (bytes not published)",
        "covered_by": "tests/package/generated_cases.py:tamper_payload",
    })
    results.append({
        "vector": "same TBS, second valid DER (equivalent generated locally)",
        "spec_reference": "§2.5 表：同一 212B TBS 不同合法 DER 5af8dff5… (bytes not published)",
        "covered_by": "golden_accept + golden_low_s_accept (two valid DERs, "
                      "one content identity, distinct package hashes)",
    })

    summary_path = args.out_dir / "spec-vectors-results.json"
    summary_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    print(f"spec vector suite: {len(results)} entries; all hash assertions and "
          f"expected result classes matched")
    print(f"results -> {summary_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"SPEC VECTOR FAILURE: {exc}", file=sys.stderr)
        raise SystemExit(1)
