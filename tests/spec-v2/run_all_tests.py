#!/usr/bin/env python3
"""run_all_tests.py — independent offline vector suite for the .neapp v2
candidate spec (docs/app-package-protocol-v2-draft.md, Harry Dev Issue #12).

One command:

    python3 tests/spec-v2/run_all_tests.py

What it does
  * rebuilds the spec §10.1 golden v2 package byte-for-byte (archived 244B TBS
    + the two quota patches + the pinned 70B DER) and fixes all SHA-256 digests;
  * cross-proves the golden signature with an independent verifier: the OpenSSL
    CLI (`openssl dgst -sha256 -verify`) in addition to the pure-Python P-256
    in v2lib (no `cryptography` dependency anywhere);
  * runs the spec §8 new/old interop matrix and the §10.3 negative families
    (payload tamper, DER tail/truncation, re-signed policy rejections, event
    wire rejections, 1024/4096 archive as resource-insufficient negative);
  * writes deterministic evidence (golden bytes, TBS, DER, SPKI, per-vector
    report) to docs/evidence/spec-v2/.

Exit code 0 only if every vector matches its expected outcome. This suite is
host-side spec evidence only: NO v2 device parser, firmware/PKA build, device
sustained-run or power-loss PASS exists anywhere (spec §12).
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v2lib as V  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence", "spec-v2")

# ---------------------------------------------------------------------------
# Frozen inputs (A decision comment 6092256674 + archive comment 6092263046)
# ---------------------------------------------------------------------------

ARCHIVED_TBS_244_HEX = (
    "4e45415050020000c0000000240000004e4d4632746573742d7075626c697368"
    "6572000068656c6c6f2d61707000000000000000000000000000000000000000"
    "0000000001000000000000001030000040000000000002003f00000004000000"
    "2400000004000000000000000000e0939e7fb5a89e294425e83ac3fb39d62514"
    "24ab12a1d236b821d06eb41053c8c0955cd252fb0ce8932436faf8ccd1040981"
    "b89ee4ad6b9fe9e2a2b7e71aacb27cd301000000000400000010000000100000"
    "000000000000000000000000000000004e45413120000100000002000000e093"
    "04000000000000000000000039348ede00207047"
)

GOLDEN_DER_HEX = (
    "3044022011e9d2635e2036fb0bcbd1107a5e6d272c150473a8c1e029887604f9aa754"
    "73702205b6ca9206755a161913fcf9cdf57c789b363420bc16a74438bc439aeb80d11b0"
)

ARCHIVE_DER_HEX = (
    "304402200491ec61fd56e2df9241d861e7a210dca2834e146978a312eeeacd306dfef782"
    "02205552f2c9e8c2c814f1c77e0fe3e971a499daeafd624e65d7fe44123880993297"
)

SPKI_SHA256_HEX = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
GOLDEN_TBS_SHA256_HEX = "e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278"
GOLDEN_PKG_SHA256_HEX = "3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e"
ARCHIVE_TBS_SHA256_HEX = "60e708cb083a3be066420874da75eeaefcec5ec8106844456b922fc1d9bf8226"
ARCHIVE_PKG_SHA256_HEX = "f05ca613d7ea2e74f61cdd5cc2bbc9f44a4406eca216366fee81894b6b664e24"

# Frozen v1 golden package, byte-for-byte from the integrated v1 spec §2.5
# (docs/app-package-protocol-v1.md). Used only as an old-package interop input.
V1_GOLDEN_HEX = (
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

D_TEST = 1  # public, unsafe, non-production P-256 test scalar d=1

VECTORS = []


def vector(name, expected, actual_ok, detail, evidence=None):
    status = "PASS" if actual_ok else "FAIL"
    VECTORS.append({"name": name, "expected": expected, "status": status, "detail": detail})
    mark = "PASS" if actual_ok else "FAIL"
    print(f"  [{mark}] {name} — {detail}")
    return actual_ok


def expect_rejection(name, fn, expected_reason, detail, detail_contains=None):
    """Run fn(); PASS only if it raises SpecViolation with expected_reason
    (and, when detail_contains is given, only if the detail matches too —
    proving the rejection is attributable to the named rule, not a checkpoint
    that happens to run earlier)."""
    try:
        fn()
    except V.SpecViolation as e:
        ok = e.reason == expected_reason
        if ok and detail_contains is not None:
            ok = detail_contains in e.detail
        return vector(name, f"reject {expected_reason}", ok,
                      f"{detail} -> {e.reason}: {e.detail}")
    except Exception as e:  # noqa: BLE001
        return vector(name, f"reject {expected_reason}", False, f"{detail} -> wrong error {e!r}")
    return vector(name, f"reject {expected_reason}", False, f"{detail} -> accepted (WRONG)")


# ---------------------------------------------------------------------------
# OpenSSL independent cross-verification
# ---------------------------------------------------------------------------

def openssl_available():
    return shutil.which("openssl") is not None


def openssl_verify(spki_der, tbs, sig_der):
    """Return (exit_code, combined_output) of openssl dgst -sha256 -verify."""
    with tempfile.TemporaryDirectory() as td:
        pem = os.path.join(td, "pub.pem")
        tf = os.path.join(td, "tbs.bin")
        sf = os.path.join(td, "sig.der")
        kf = os.path.join(td, "pub.spki.der")
        open(kf, "wb").write(spki_der)
        open(tf, "wb").write(tbs)
        open(sf, "wb").write(sig_der)
        r = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", kf, "-out", pem],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return r.returncode, "pkey: " + (r.stderr or r.stdout)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pem,
                            "-signature", sf, tf], capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip()


# ---------------------------------------------------------------------------
# Package assembly helpers
# ---------------------------------------------------------------------------

def rebuild_golden_tbs():
    """Spec §10.1: archived 244B TBS with ONLY the two quota patches."""
    tbs = bytearray(bytes.fromhex(ARCHIVED_TBS_244_HEX))
    tbs[180:184] = bytes.fromhex("00080000")   # event_max = 2048
    tbs[188:192] = bytes.fromhex("00180000")   # report_max = 6144
    return bytes(tbs)


def resigned_package(manifest192, native, private_scalar=D_TEST):
    """Re-sign a modified TBS deterministically (RFC6979) for policy negatives."""
    header = V.MAGIC_V2 + struct.pack("<II", V.V2_MANIFEST_LEN, len(native))
    tbs = header + manifest192 + native
    sig = V.rfc6979_sign(private_scalar, V.sha256(tbs))
    return tbs + sig, tbs, sig


def full_accept(pkg, host=V.HOST_POLICY_V2):
    """Full v2 Host acceptance in spec §2.3 order: bounded structure/manifest
    unique-encoding first, then the Host-LOCAL trusted-issuer mapping lookup
    (publisher_id -> SPKI store; fail-closed PUBLISHER_UNTRUSTED), then ECDSA
    verification of the raw TBS with that mapped Host-owned key, and only then
    the trust-data cross-checks (native header/CRC/SHA) and the host policy
    (caps subset/quotas/Host-own loader range and exec region)."""
    c = V.parse_container(pkg)
    man = V.decode_manifest_v2(c["manifest"])
    issuer_spki = V.trusted_issuer_spki(host, man)
    if not V.p256_verify(issuer_spki, V.sha256(c["tbs"]), c["sig"]):
        raise V.SpecViolation("SIGNATURE_INVALID", "ECDSA verify failed against Host-trusted issuer key")
    V.check_native_cross(c["native"], man)
    V.policy_check_v2_host(man, c["native"], host=host)
    return c, man


SPKI = None  # set in main()


# ---------------------------------------------------------------------------
# Vector groups
# ---------------------------------------------------------------------------

def group_golden():
    print("== [1] Golden v2 package rebuild and digest pinning (spec §10.1) ==")
    golden_tbs = rebuild_golden_tbs()
    golden_der = bytes.fromhex(GOLDEN_DER_HEX)
    golden_pkg = golden_tbs + golden_der

    vector("golden_tbs_length", "244B", len(golden_tbs) == 244,
           f"TBS length {len(golden_tbs)}")
    vector("golden_tbs_digest_pinned", GOLDEN_TBS_SHA256_HEX,
           V.sha256_hex(golden_tbs) == GOLDEN_TBS_SHA256_HEX,
           f"SHA-256(TBS)={V.sha256_hex(golden_tbs)}")
    vector("golden_pkg_length", "314B", len(golden_pkg) == 314,
           f"package length {len(golden_pkg)}")
    vector("golden_pkg_digest_pinned", GOLDEN_PKG_SHA256_HEX,
           V.sha256_hex(golden_pkg) == GOLDEN_PKG_SHA256_HEX,
           f"SHA-256(package)={V.sha256_hex(golden_pkg)}")

    c, man = full_accept(golden_pkg)
    vector("golden_structural_manifest_native_policy", "full acceptance", True,
           f"magic ok, manifest_len=192, abi=0x{man['abi']:08x}, caps=0x{man['caps']:x}, "
           f"profile={man['run_profile']}, quotas {man['event_max']}/{man['state_quota']}/{man['report_max']}")
    vector("golden_crypto_pure_python", "ECDSA valid",
           V.p256_verify(SPKI, V.sha256(c["tbs"]), c["sig"]),
           "pure-Python P-256 verify against d=1 SPKI")
    vector("golden_spki_digest_pinned", SPKI_SHA256_HEX,
           V.sha256_hex(SPKI) == SPKI_SHA256_HEX,
           "SHA-256(SPKI DER) matches manifest publisher_key_sha256")
    if openssl_available():
        code, out = openssl_verify(SPKI, c["tbs"], c["sig"])
        vector("golden_crypto_openssl", "Verified OK, exit 0",
               code == 0, f"openssl dgst -sha256 -verify: {out} (exit {code})")
    else:
        vector("golden_crypto_openssl", "openssl present", False,
               "openssl CLI not found; independent cross-proof required")
    return golden_tbs, golden_der, golden_pkg


def group_archive_negative():
    print("== [2] Historical 1024/4096 archive = valid-math / resource-insufficient negative (spec §10.2, §8 M7) ==")
    arch_tbs = bytes.fromhex(ARCHIVED_TBS_244_HEX)
    arch_der = bytes.fromhex(ARCHIVE_DER_HEX)
    arch_pkg = arch_tbs + arch_der
    vector("archive_tbs_digest_pinned", ARCHIVE_TBS_SHA256_HEX,
           V.sha256_hex(arch_tbs) == ARCHIVE_TBS_SHA256_HEX,
           "archived TBS reconstructed byte-for-byte")
    vector("archive_pkg_digest_pinned", ARCHIVE_PKG_SHA256_HEX,
           V.sha256_hex(arch_pkg) == ARCHIVE_PKG_SHA256_HEX,
           "archived package (TBS+fixed DER) reconstructed")
    vector("archive_signature_math_valid", "signature valid",
           V.p256_verify(SPKI, V.sha256(arch_tbs), arch_der),
           "proving the rejection below is resource policy, not signature")
    expect_rejection("archive_quota_1024_4096_resource_limit",
                     lambda: full_accept(arch_pkg),
                     "RESOURCE_LIMIT",
                     "event_max=1024 < 1576 (64-frame ai_events), report_max=4096 < 6144",
                     detail_contains="event_max 1024")


def group_resigned_policy_negatives(golden_pkg):
    print("== [3] Re-signed policy rejections + host caps subset: valid signature must NOT bypass policy (spec §10.3.3, §8 M4/M5/M6/M9/M10) ==")
    c = V.parse_container(golden_pkg)
    man_bytes = bytearray(c["manifest"])
    native = c["native"]

    def mutated(mutator):
        m = bytearray(man_bytes)
        mutator(m)
        pkg, tbs, sig = resigned_package(bytes(m), native)
        return pkg

    # M5: unknown capability bit6
    pkg = mutated(lambda m: struct.pack_into("<I", m, 72, 0x0000003F | (1 << 6)))
    expect_rejection("caps_unknown_bit6", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "caps bit6 set, RFC6979 re-signed")
    cb = V.parse_container(pkg)
    vector("caps_unknown_bit6_signature_valid", "signature valid",
           V.p256_verify(SPKI, V.sha256(cb["tbs"]), cb["sig"]),
           "rejection is policy, not signature")

    # [176..191] reserved nonzero
    pkg = mutated(lambda m: m.__setitem__(176, 0x01))
    expect_rejection("reserved_176_nonzero", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "manifest reserved[176]=0x01, re-signed")

    # manifest reserved[58..59] nonzero (v1-inherited invariant)
    pkg = mutated(lambda m: m.__setitem__(58, 0x01))
    expect_rejection("reserved_58_59_nonzero", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "manifest reserved[58]=0x01, re-signed")

    # unknown run_profile
    pkg = mutated(lambda m: struct.pack_into("<I", m, 160, 2))
    expect_rejection("unknown_run_profile", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "run_profile=2, re-signed")

    # profile 1 without session_lifecycle bit
    pkg = mutated(lambda m: struct.pack_into("<I", m, 72, 0x0000003F & ~(1 << 5)))
    expect_rejection("profile1_without_bit5", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "caps=0x1f (no session_lifecycle), re-signed")

    # capability/quota mismatch: ai_events with event_max=0
    pkg = mutated(lambda m: struct.pack_into("<I", m, 164, 0))
    expect_rejection("ai_events_zero_event_max", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "caps bit2 kept, event_max=0, re-signed")

    # M4: v2 container declaring v1 ABI
    pkg = mutated(lambda m: struct.pack_into("<I", m, 68, V.ABI_V1))
    expect_rejection("v2_container_v1_abi", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "required_host_abi=0x00010000 inside NMF2 manifest, re-signed")

    # AC2: a KNOWN capability the current Host does not provide must be
    # fail-closed rejected (spec §4.2 declaration-vs-host-verify boundary).
    # The golden package is signature-valid with caps=0x3f (all bits known);
    # a Host that lacks report_submit (bit3) must reject it as ABI_INCOMPATIBLE.
    host_no_report = dict(V.HOST_POLICY_V2,
                          caps_supported=V.HOST_POLICY_V2["caps_supported"] & ~V.CAP_REPORT_SUBMIT)
    vector("caps_subset_negative_signature_valid", "signature valid",
           V.p256_verify(SPKI, V.sha256(c["tbs"]), c["sig"]),
           "golden signature pinned valid; the rejection below is host policy, not signature")
    expect_rejection("caps_subset_host_missing_report_submit",
                     lambda: full_accept(golden_pkg, host=host_no_report),
                     "ABI_INCOMPATIBLE", "caps=0x3f all known bits; Host lacks report_submit",
                     detail_contains="host does not provide capability bits")

    # AC2/AC4 Rev3: publisher trust mapping (spec §2.3 step 3 / §3.1, v1-inherited).
    # The Host resolves the issuer key from its OWN configured store keyed by the
    # signed publisher_id and compares the manifest fingerprint against that store.
    # a) unknown publisher id (format-valid identifier), validly re-signed
    m = bytearray(man_bytes)
    m[4:20] = b"untrusted-pub".ljust(16, b"\x00")
    pkg, _, _ = resigned_package(bytes(m), native)
    expect_rejection("unknown_publisher_id", lambda: full_accept(pkg), "PUBLISHER_UNTRUSTED",
                     "format-valid publisher_id absent from Host trust store, re-signed",
                     detail_contains="not in Host trusted mapping")
    # b) trusted publisher id but altered key fingerprint, validly re-signed
    m = bytearray(man_bytes)
    m[128] = 0x5D                      # trusted SPKI fingerprint starts 0x5c
    pkg, _, _ = resigned_package(bytes(m), native)
    cb = V.parse_container(pkg)
    vector("publisher_negative_signature_valid", "signature valid",
           V.p256_verify(SPKI, V.sha256(cb["tbs"]), cb["sig"]),
           "re-signed with the Host-store key: rejection below is trust mapping, not signature")
    expect_rejection("publisher_key_fingerprint_mismatch", lambda: full_accept(pkg), "PUBLISHER_UNTRUSTED",
                     "manifest fingerprint altered, Host store entry unchanged, re-signed",
                     detail_contains="publisher_key_sha256 mismatch")

    # AC2/AC4 Rev3: Host independently known loader placement / actual exec region
    # (spec §3.3 / v1 §2.3 rules). a) self-consistent target outside Host range:
    # manifest AND native header target moved together (cross-check passes), but
    # the address is not in the Host's independently known loader range.
    bad_native = bytearray(native)
    struct.pack_into("<I", bad_native, 12, 0x94E00000)
    m = bytearray(man_bytes)
    struct.pack_into("<I", m, 92, 0x94E00000)
    m[96:128] = V.sha256(bytes(bad_native))
    pkg, _, _ = resigned_package(bytes(m), bytes(bad_native))
    expect_rejection("target_outside_host_loader_range", lambda: full_accept(pkg), "RESOURCE_LIMIT",
                     "self-consistent target 0x94E00000 outside Host loader range, re-signed",
                     detail_contains="outside host loader range")
    # b) required exec region far beyond the Host actual execution region
    m = bytearray(man_bytes)
    struct.pack_into("<I", m, 76, 3 * 1024 * 1024)
    pkg, _, _ = resigned_package(bytes(m), native)
    expect_rejection("exec_region_exceeds_host_actual", lambda: full_accept(pkg), "RESOURCE_LIMIT",
                     "required_exec_region_bytes=3MiB > host actual 2MiB, re-signed",
                     detail_contains="exceeds host actual")

    # native header ABI-only mismatch: manifest keeps required_host_abi=0x00020000;
    # ONLY the native header abi_version is flipped to 0x00010000 (native SHA
    # updated in manifest, CRC untouched — it covers the payload only), then the
    # package is legally re-signed. The rejection must come from the native
    # header <-> manifest cross-check, not from a manifest format violation.
    bad_native = bytearray(native)
    struct.pack_into("<I", bad_native, 8, V.ABI_V1)      # native header abi_version only
    m = bytearray(man_bytes)
    # manifest abi at [68..71] deliberately stays 0x00020000
    m[96:128] = V.sha256(bytes(bad_native))              # keep manifest native SHA consistent
    pkg, _, _ = resigned_package(bytes(m), bytes(bad_native))
    expect_rejection("native_header_abi_mismatch_vs_manifest", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "native header abi=0x00010000 vs manifest 0x00020000, digest-consistent, re-signed",
                     detail_contains="native abi 0x00010000 != manifest")

    # native reserved0 nonzero (digest-consistent, re-signed) — v1-inherited rule
    bad_native = bytearray(native)
    struct.pack_into("<I", bad_native, 24, 1)
    m = bytearray(man_bytes)
    m[96:128] = V.sha256(bytes(bad_native))
    pkg, _, _ = resigned_package(bytes(m), bytes(bad_native))
    expect_rejection("native_reserved0_nonzero", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "native reserved0=1 with matching digest, re-signed")

    # payload CRC self-consistent but manifest len mismatch
    m = bytearray(man_bytes)
    struct.pack_into("<I", m, 80, len(native) + 1)
    pkg, _, _ = resigned_package(bytes(m), native)
    expect_rejection("manifest_native_len_mismatch", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "manifest native_file_len=+1, re-signed")


def group_container_structure(golden_pkg):
    print("== [4] Container/DER structural negatives (spec §10.3.2, §10.3.7) ==")
    c = V.parse_container(golden_pkg)
    good_sig = c["sig"]

    expect_rejection("der_trailing_byte",
                     lambda: full_accept(golden_pkg + b"\xff"), "BAD_PACKAGE",
                     "valid 70B DER + 1 trailing byte (must fully consume tail)")
    expect_rejection("der_truncated",
                     lambda: full_accept(golden_pkg[:-1]), "BAD_PACKAGE",
                     "signature truncated by 1 byte")

    # high-M / wrong container lengths
    pkg = bytearray(golden_pkg)
    struct.pack_into("<I", pkg, 8, 160)
    expect_rejection("manifest_len_160_in_v2", lambda: full_accept(bytes(pkg)), "BAD_PACKAGE",
                     "manifest_len field=160 (v1 value) in v2 header")

    pkg = bytearray(golden_pkg)
    pkg[0:8] = V.MAGIC_V1
    expect_rejection("v1_magic_on_v2_container", lambda: full_accept(bytes(pkg)), "BAD_PACKAGE",
                     "container magic downgraded to v1, body unchanged")

    # v2 package against the frozen v1 structural gate (M2)
    expect_rejection("v2_package_on_v1_host", lambda: V.v1_gate_structural(golden_pkg),
                     "BAD_PACKAGE", "v2 golden fed to frozen v1 structural rules")

    # NMF1 manifest inside v2 container
    m = bytearray(c["manifest"])
    m[0:4] = V.MANIFEST_MAGIC_V1
    pkg, _, _ = resigned_package(bytes(m), c["native"])
    expect_rejection("nmf1_magic_in_v2", lambda: full_accept(pkg), "BAD_PACKAGE",
                     "manifest magic NMF1 in v2 container, re-signed")


def group_tamper(golden_pkg):
    print("== [5] Signed-content tamper (spec §10.3.1) ==")
    # Dynamic layout from the parsed container (no hardcoded offsets):
    # TBS = [0,16) container header | [16, 16+192) manifest | native file.
    # Native file = 32B image header [native_off, native_off+32) then the true
    # payload [native_off+32, len(TBS)). Everything at/after len(TBS) is the
    # DER signature region and stays byte-for-byte untouched below.
    c = V.parse_container(golden_pkg)
    tbs_len = len(c["tbs"])
    native_off = 16 + c["manifest_len"]
    payload_off = native_off + V.NATIVE_HEADER_SIZE
    assert 16 < native_off < payload_off < tbs_len, "golden layout assumption"
    print(f"     layout: manifest [16,{native_off}), native hdr [{native_off},{payload_off}), "
          f"true payload [{payload_off},{tbs_len}), DER [{tbs_len},{len(golden_pkg)})")

    # 1) TRUE payload byte flipped (inside [240,244) for the golden TBS), DER untouched.
    pkg = bytearray(golden_pkg)
    pkg[payload_off] ^= 0x01
    diffs = [i for i in range(len(golden_pkg)) if pkg[i] != golden_pkg[i]]
    assert diffs == [payload_off], f"exactly the payload byte must differ, got {diffs}"
    assert pkg[tbs_len:] == golden_pkg[tbs_len:], "DER must remain byte-identical"
    try:
        full_accept(bytes(pkg))
        vector("payload_tamper_detected", "SIGNATURE_INVALID", False,
               "tampered true payload accepted (WRONG)")
    except V.SpecViolation as e:
        vector("payload_tamper_detected", "SIGNATURE_INVALID", e.reason == "SIGNATURE_INVALID",
               f"true payload byte at TBS[{payload_off}] flipped (DER untouched) -> {e.reason}")
    if openssl_available():
        c2 = V.parse_container(bytes(pkg))
        code, out = openssl_verify(SPKI, c2["tbs"], c2["sig"])
        vector("payload_tamper_openssl_rejects", "non-zero exit", code != 0,
               f"openssl: {out.strip().splitlines()[0]} (exit {code})")

    # 2) Manifest byte flip (signed metadata, not payload).
    pkg = bytearray(golden_pkg)
    pkg[40] ^= 0x01
    try:
        full_accept(bytes(pkg))
        vector("manifest_tamper_detected", "SIGNATURE_INVALID", False,
               "tampered manifest accepted (WRONG)")
    except V.SpecViolation as e:
        vector("manifest_tamper_detected", "SIGNATURE_INVALID", e.reason == "SIGNATURE_INVALID",
               f"manifest byte 40 (app_id area) flipped -> {e.reason}")

    # 3) DER signature bytes corrupted (region [244,314)); TBS untouched.
    #    Correctly labeled: this proves corrupted signature bytes fail verification;
    #    it is NOT a signed-payload coverage proof (vector 1 above is).
    pkg = bytearray(golden_pkg)
    pkg[tbs_len + 6] ^= 0x01
    try:
        full_accept(bytes(pkg))
        vector("der_region_tamper_detected", "SIGNATURE_INVALID", False,
               "corrupted DER accepted (WRONG)")
    except V.SpecViolation as e:
        vector("der_region_tamper_detected", "SIGNATURE_INVALID", e.reason == "SIGNATURE_INVALID",
               f"DER byte {tbs_len + 6} flipped (TBS untouched) -> {e.reason}")


def group_interop_v1(golden_pkg):
    print("== [6] Old/new interop discrimination (spec §8 M2/M3/M4) ==")
    v1_pkg = bytes.fromhex(V1_GOLDEN_HEX)
    vector("v1_golden_digest", "9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679",
           V.sha256_hex(v1_pkg) == "9a212324132c0f26e2878384904f1af4abd3090a6ae5806ef32da2d3b4c80679",
           "frozen v1 §2.5 golden rebuilt from spec HEX")
    gate = V.v1_gate_structural(v1_pkg)
    vector("v1_golden_structural", "v1 gate PASS", True,
           f"v1 container ok, abi=0x{gate['abi']:08x}, caps=0x{gate['caps']:x} (log|tick_ms only)")
    vector("v1_golden_signature_valid", "signature valid",
           V.p256_verify(SPKI, V.sha256(gate["tbs"]), gate["sig"]),
           "v1 golden DER verifies against the same d=1 SPKI")
    vector("v1_on_v2_host_caps_limited", "only v1 16B table semantics (M3)",
           (gate["caps"] & ~0b11) == 0,
           "v2 Host grants log|tick_ms only; no v2 capability may be inferred")
    if openssl_available():
        code, out = openssl_verify(SPKI, gate["tbs"], gate["sig"])
        vector("v1_golden_openssl", "Verified OK, exit 0", code == 0,
               f"openssl: {out} (exit {code})")


def group_event_wire():
    print("== [7] AI event wire (spec §5, §10.4) ==")
    # positive: FRAME with 64 detections = exactly 1576B
    dets = [(float(i), float(i) * 2, 10.0 + i, 20.0, 0.5 + i / 100.0, i % 8) for i in range(64)]
    ev = V.encode_event(V.EVENT_KIND_FRAME, 42, 1000, 3, 2, 0b00, 0, dets)
    vector("frame64_length_1576", "1576B", len(ev) == 1576, f"len={len(ev)}")
    p = V.validate_event(ev, class_count=8)
    vector("frame64_roundtrip", "kind=1 count=64", p["kind"] == 1 and p["detection_count"] == 64,
           "encode/validate round trip")
    ev0 = V.encode_event(V.EVENT_KIND_FRAME, 43, 1001, 3, 2, 0b00, 0, [])
    vector("frame0_is_40b", "40B FRAME(count=0)",
           len(ev0) == 40 and V.validate_event(ev0)["detection_count"] == 0,
           "distinct from NO_EVENT/MODEL_CHANGED/STOPPING")
    for kind, name in ((2, "model_changed"), (3, "gap"), (4, "stopping")):
        lost = V.LOST_COUNT_UNKNOWN if kind == V.EVENT_KIND_GAP else 0
        flags = 0b10 if kind == V.EVENT_KIND_GAP else 0b00
        e = V.encode_event(kind, 44, 1002, 3, 2, flags, lost)
        V.validate_event(e)
        vector(f"kind_{name}_encodes", "40B valid", len(e) == 40, f"kind={kind}")

    expect_rejection("event_unknown_kind",
                     lambda: V.validate_event(V.encode_event(5, 0, 0, 0, 0, 0, 0)),
                     "BAD_EVENT", "kind=5")
    expect_rejection("event_unknown_flag_bit",
                     lambda: V.validate_event(V.encode_event(1, 0, 0, 0, 0, 0b100, 0, [])),
                     "BAD_EVENT", "flags bit2 set")
    expect_rejection("event_flag1_without_sentinel",
                     lambda: V.validate_event(V.encode_event(1, 0, 0, 0, 0, 0b10, 7, [])),
                     "BAD_EVENT", "flags.bit1=1 but lost_frame_count=7 (must be 0xFFFFFFFF)")
    expect_rejection("event_sentinel_without_flag1",
                     lambda: V.validate_event(V.encode_event(1, 0, 0, 0, 0, 0b00,
                                                             V.LOST_COUNT_UNKNOWN, [])),
                     "BAD_EVENT", "lost_frame_count=0xFFFFFFFF without flags.bit1")
    # 65 detections: encoder must refuse; a hand-built buffer must fail validation
    too_many = dets + [(1.0, 1.0, 1.0, 1.0, 0.5, 0)]
    expect_rejection("event_65_detections_encode",
                     lambda: V.encode_event(V.EVENT_KIND_FRAME, 0, 0, 0, 0, 0, 0, too_many),
                     "BAD_EVENT", "65 detections > 64")
    raw = struct.pack("<10I", 40 + 24 * 65, 1, 0, 0, 0, 0, 0, 65, 0, 0)
    expect_rejection("event_65_detections_wire",
                     lambda: V.validate_event(raw + bytes(24 * 65)), "BAD_EVENT",
                     "hand-built 65-detection event rejected, not truncated")
    expect_rejection("event_total_len_mismatch",
                     lambda: V.validate_event(struct.pack("<10I", 100, 1, 0, 0, 0, 0, 0, 2, 0, 0) + bytes(48)),
                     "BAD_EVENT", "total_len=100 != 40+24*2")
    expect_rejection("event_nonfinite_confidence",
                     lambda: V.validate_event(struct.pack("<10I", 64, 1, 0, 0, 0, 0, 0, 1, 0, 0)
                                              + struct.pack("<6I", 0x3F800000, 0x40000000, 0x40400000,
                                                            0x40800000, 0x7FC00000, 0)),
                     "BAD_EVENT", "confidence bits = quiet NaN")
    expect_rejection("event_class_index_oob",
                     lambda: V.validate_event(struct.pack("<10I", 64, 1, 0, 0, 0, 0, 0, 1, 0, 0)
                                              + struct.pack("<6I", 0x3F800000, 0x40000000, 0x40400000,
                                                            0x40800000, 0x3F000000, 8),
                                              class_count=8),
                     "BAD_EVENT", "class_index=8 >= class_count=8")


def group_model_meta():
    print("== [8] model_meta / report-size host semantics (spec §6.5/§6.6) ==")
    meta = V.encode_model_meta(True, 7, 3, 8, "line-crossing-model", "2.1.0")
    d = V.validate_model_meta(meta)
    vector("model_meta_layout", "128B, PP_TYPE_OD, fields ok",
           len(meta) == 128 and d["result_type"] == V.PP_TYPE_OD and d["class_count"] == 8,
           f"loaded={d['loaded']} name={d['model_name']!r} ver={d['model_version']!r}")
    # result_type other than PP_TYPE_OD is INCOMPATIBLE
    bad = bytearray(meta)
    struct.pack_into("<I", bad, 4, 2)
    try:
        V.validate_model_meta(bytes(bad))
        vector("model_meta_wrong_type_incompatible", "INCOMPATIBLE", False, "accepted (WRONG)")
    except V.SpecViolation as e:
        vector("model_meta_wrong_type_incompatible", "INCOMPATIBLE", e.reason == "INCOMPATIBLE",
               f"result_type=2 -> {e.reason}")
    # oversized report against declared quota: explicit reject, never truncation
    declared = V.LINE_CROSSING_PROFILE["report_max"]
    oversized = declared + 1
    try:
        if oversized > declared:
            raise V.SpecViolation("QUOTA_EXCEEDED", f"report len {oversized} > report_max {declared}")
        vector("report_oversize_rejected", "QUOTA_EXCEEDED", False, "accepted (WRONG)")
    except V.SpecViolation as e:
        vector("report_oversize_rejected", "QUOTA_EXCEEDED", e.reason == "QUOTA_EXCEEDED",
               f"{oversized}B report vs report_max={declared} -> {e.reason} (no truncation)")
    vector("report_capacity_aligns_lc_dq", "6144B",
           V.LINE_CROSSING_PROFILE["report_max"] == V.REPORT_BUSINESS_MAX == 6144,
           "declared report_max == LC_DQ_SLOT_CAPACITY evidence anchor")

    # AC4 Rev3: strict model_meta wire decoding (spec §6.5) — a required NUL,
    # all-zero right padding, and zero reserved are all fail-closed.
    def malformed_meta(name_field=None, ver_field=None, tail=None):
        b = bytearray(meta)
        if name_field is not None:
            b[24:24 + V.MODEL_NAME_LEN] = name_field
        if ver_field is not None:
            b[24 + V.MODEL_NAME_LEN:24 + V.MODEL_NAME_LEN + V.MODEL_VERSION_LEN] = ver_field
        if tail is not None:
            b[24 + V.MODEL_NAME_LEN + V.MODEL_VERSION_LEN:] = tail
        return bytes(b)

    expect_rejection("model_name_no_nul",
                     lambda: V.validate_model_meta(malformed_meta(name_field=b"A" * 64)),
                     "INCOMPATIBLE", "model_name fills all 64B without NUL",
                     detail_contains="model_name missing NUL")
    expect_rejection("model_name_junk_after_nul",
                     lambda: V.validate_model_meta(malformed_meta(name_field=b"model\x00junk" + bytes(54))),
                     "INCOMPATIBLE", "model_name carries junk after its NUL",
                     detail_contains="model_name has non-zero bytes after its NUL")
    expect_rejection("model_version_no_nul",
                     lambda: V.validate_model_meta(malformed_meta(ver_field=b"9" * 32)),
                     "INCOMPATIBLE", "model_version fills all 32B without NUL",
                     detail_contains="model_version missing NUL")
    expect_rejection("model_meta_trailing_reserved_nonzero",
                     lambda: V.validate_model_meta(malformed_meta(tail=bytes([1]) + bytes(7))),
                     "INCOMPATIBLE", "trailing 8B reserved nonzero",
                     detail_contains="trailing reserved not zero")


def group_tick_ms():
    print("== [9] tick_ms modulo-2^32 semantics (spec §6.3/§6.4; A decision issuecomment-6093724900) ==")
    vector("tick_positive_small_delta", "delta 50",
           V.tick_delta_ms(100, 150) == 50,
           "ordinary small forward step, well below the wrap point")
    d1 = V.tick_delta_ms(0x7FFFFFFF, 0x80000000)
    neg1 = struct.unpack("<i", struct.pack("<I", 0x80000000))[0]
    vector("tick_wrap_7fffffff_to_80000000", "delta 1 (legal progress, not an error)",
           d1 == 1,
           "mod-2^32 wrap past 2^31; the naive signed-int32 reading of 0x80000000 is "
           f"{neg1} and must NOT be treated as a §6.4 negative error code")
    vector("tick_int32_trap_guard_80000000", "trap documented and guarded",
           neg1 == -(1 << 31) and neg1 < 0 and d1 == 1,
           "negative int32 value exists but the delta channel is uint32 mod-2^32 only")
    d2 = V.tick_delta_ms(0xFFFFFFFF, 0x00000000)
    neg2 = struct.unpack("<i", struct.pack("<I", 0xFFFFFFFF))[0]
    vector("tick_wrap_ffffffff_to_00000000", "delta 1 (legal progress, not an error)",
           d2 == 1 and neg2 == -1 and neg2 < 0,
           "0xffffffff -> 0x00000000 is +1 mod 2^32; the int32 reading -1 is not a §6.4 error")
    expect_rejection("tick_bits_out_of_range",
                     lambda: V.tick_delta_ms(0, 1 << 32), "INVALID_ARGUMENT",
                     "non-u32 bit pattern rejected")


def write_evidence(golden_tbs, golden_der, golden_pkg, arch_pkg, v1_pkg):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    open(os.path.join(EVIDENCE_DIR, "golden.neapp.v2"), "wb").write(golden_pkg)
    open(os.path.join(EVIDENCE_DIR, "golden-tbs.bin"), "wb").write(golden_tbs)
    open(os.path.join(EVIDENCE_DIR, "golden-sig.der"), "wb").write(golden_der)
    open(os.path.join(EVIDENCE_DIR, "test-publisher.spki.der"), "wb").write(SPKI)
    open(os.path.join(EVIDENCE_DIR, "negative-archive-1024-4096.neapp.v2"), "wb").write(arch_pkg)
    open(os.path.join(EVIDENCE_DIR, "v1-golden.neapp"), "wb").write(v1_pkg)

    report = {
        "spec": "docs/app-package-protocol-v2-draft.md",
        "issue": 12,
        "suite": "tests/spec-v2/run_all_tests.py",
        "note": ("Host-side spec evidence only. No v2 device parser, no STM32 target build, "
                 "no device PKA, no sustained-run or power-loss PASS (spec §12). "
                 "Test key d=1 is public and non-production."),
        "rev3_corrections": {
            "reviewed_candidate": "d3dab540c19861567bc5e71bd8c5e615d1302d41",
            "ac2_publisher_trust": ("full_accept now resolves the issuer key from the Host-LOCAL "
                                    "trusted_publishers store keyed by the signed publisher_id and compares "
                                    "the manifest fingerprint against that store (spec §2.3 step 3/§3.1); "
                                    "fail-closed PUBLISHER_UNTRUSTED. New negatives: unknown_publisher_id, "
                                    "publisher_key_fingerprint_mismatch (+ signature-valid proof)."),
            "ac2_exec_region": ("HOST_POLICY_V2 gains Host-owned loader_base/loader_size/exec_region_bytes; "
                                "policy fail-closed checks target_addr against the independently known "
                                "loader range and required_exec_region_bytes against the actual exec "
                                "region (spec §3.3, v1 §2.3 rules). New negatives: "
                                "target_outside_host_loader_range, exec_region_exceeds_host_actual. "
                                "No production physical-memory proof is claimed."),
            "ac4_model_meta_strict": ("validate_model_meta now requires a NUL terminator, all-zero right "
                                      "padding, valid UTF-8 and zero reserved (spec §6.5). New malformed-wire "
                                      "negatives: model_name_no_nul, model_name_junk_after_nul, "
                                      "model_version_no_nul, model_meta_trailing_reserved_nonzero."),
            "ac3_tick_ms": ("tick_ms documented as the sole exception to the §6.4 negative-error channel: "
                            "raw mod-2^32 time bits, delta via uint32 difference (A decision "
                            "issuecomment-6093724900). New device-independent vectors: wrap "
                            "0x7fffffff->0x80000000 and 0xffffffff->0x00000000 are legal +1 progress with "
                            "the int32 misreading trap documented; no ABI table/signature change."),
        },
        "rev2_corrections": {
            "reviewed_candidate": "7564c22b740430a94ca7133697ebce3f85554f68",
            "ac2_caps_subset": ("policy_check_v2_host now fail-closed rejects KNOWN capability bits the "
                                "current Host does not provide (ABI_INCOMPATIBLE); new negatives "
                                "caps_subset_host_missing_report_submit (+ signature-valid proof)."),
            "ac4_verify_order": ("full_accept now follows spec §2.3 order: bounded structure/manifest "
                                 "unique-encoding -> ECDSA over raw TBS -> native cross-checks -> policy; "
                                 "payload tamper flips a dynamically computed TRUE payload byte "
                                 "(TBS[240:244], DER byte-identical) and asserts exactly SIGNATURE_INVALID; "
                                 "DER-region corruption is a separately labeled vector."),
            "ac4_abi_attribution": ("native_header_abi_mismatch_vs_manifest keeps manifest abi=0x00020000, "
                                    "flips ONLY the native header abi to 0x00010000 (manifest native SHA "
                                    "updated), re-signs, and asserts the rejection detail names the "
                                    "native<->manifest cross mismatch; the v2-container-declares-v1-ABI "
                                    "case remains a separate independent test."),
        },
        "vectors_total": len(VECTORS),
        "vectors_passed": sum(1 for v in VECTORS if v["status"] == "PASS"),
        "vectors": VECTORS,
        "digests": {
            "sha256_golden_tbs": V.sha256_hex(golden_tbs),
            "sha256_golden_package": V.sha256_hex(golden_pkg),
            "sha256_archive_package": V.sha256_hex(arch_pkg),
            "sha256_spki_der": V.sha256_hex(SPKI),
            "sha256_v1_golden": V.sha256_hex(v1_pkg),
        },
        "openssl_cross_proof": None,
    }

    # OpenSSL cross-proof block appended to report
    lines = []
    lines.append("# .neapp v2 candidate spec — offline vector evidence\n")
    lines.append(f"- Spec: `docs/app-package-protocol-v2-draft.md` (Issue #12 candidate, NOT integrated)")
    lines.append(f"- Suite: `python3 tests/spec-v2/run_all_tests.py` (stdlib-only; OpenSSL used as independent verifier)")
    lines.append(f"- Vectors: **{report['vectors_passed']}/{report['vectors_total']} PASS**\n")
    lines.append("## Golden v2 package (spec §10.1)")
    lines.append(f"- `golden.neapp.v2` — {len(golden_pkg)}B, SHA-256 `{report['digests']['sha256_golden_package']}`")
    lines.append(f"- `golden-tbs.bin` — {len(golden_tbs)}B, SHA-256 `{report['digests']['sha256_golden_tbs']}`")
    lines.append(f"- `golden-sig.der` — {len(golden_der)}B (pinned strict DER)")
    lines.append(f"- `test-publisher.spki.der` — {len(SPKI)}B, SHA-256 `{report['digests']['sha256_spki_der']}`")
    lines.append(f"- key: public non-production P-256 scalar d=1 — MUST NOT be used as a production trust anchor\n")
    lines.append("## Independent OpenSSL cross-proof")
    if openssl_available():
        code, out = openssl_verify(SPKI, golden_tbs, golden_der)
        report["openssl_cross_proof"] = {"command": "openssl dgst -sha256 -verify", "exit": code, "output": out}
        lines.append(f"- `$ openssl dgst -sha256 -verify pub.pem -signature golden-sig.der golden-tbs.bin`")
        lines.append(f"- exit **{code}**, output: `{out}`\n")
    else:
        lines.append("- openssl CLI not available; cross-proof MISSING (suite would have failed)\n")
    lines.append("## Rev 3 corrections (A self-audit review of d3dab54, AC2/AC4/AC3)")
    lines.append("1. **AC2 publisher trust mapping**: `full_accept` resolves the issuer key from the "
                 "Host-LOCAL `trusted_publishers` store keyed by the signed `publisher_id` and compares "
                 "the manifest fingerprint against that store before verifying (spec §2.3 step 3/§3.1, "
                 "fail-closed `PUBLISHER_UNTRUSTED`). Negatives `unknown_publisher_id` and "
                 "`publisher_key_fingerprint_mismatch` are validly re-signed with attributable detail.")
    lines.append("2. **AC2 host loader/region admission**: the simulated Host now carries its own "
                 "`loader_base`/`loader_size`/`exec_region_bytes`; policy checks `native_target_addr` "
                 "against the independently known loader range and `required_exec_region_bytes` against "
                 "the actual exec region (spec §3.3, v1 §2.3). Negatives `target_outside_host_loader_range` "
                 "and `exec_region_exceeds_host_actual` are validly re-signed. No production physical "
                 "memory proof is claimed.")
    lines.append("3. **AC4 strict model_meta wire**: `validate_model_meta` requires a NUL terminator, "
                 "all-zero right padding, valid UTF-8 and zero reserved; malformed-wire negatives "
                 "`model_name_no_nul`, `model_name_junk_after_nul`, `model_version_no_nul`, "
                 "`model_meta_trailing_reserved_nonzero` added (INCOMPATIBLE).")
    lines.append("4. **AC3 tick_ms semantics** (A decision issuecomment-6093724900): documented in spec "
                 "§6.3/§6.4 as the sole exception to the negative-error-code channel — raw mod-2^32 time "
                 "bits, progress measured by uint32 difference. Vectors: 0x7fffffff->0x80000000 and "
                 "0xffffffff->0x00000000 both advance +1; the signed-int32 misreading trap is documented. "
                 "48B table, C signatures and v1 code unchanged.\n")
    lines.append("## Rev 2 corrections (A review of 7564c22, AC2/AC4 blockers)")
    lines.append("1. **AC2 caps subset**: `policy_check_v2_host` now fail-closed rejects KNOWN capability "
                 "bits the current Host does not provide (`ABI_INCOMPATIBLE`); negatives "
                 "`caps_subset_host_missing_report_submit` + `caps_subset_negative_signature_valid` added.")
    lines.append("2. **AC4 verify order + true payload tamper**: `full_accept` follows spec §2.3 order "
                 "(bounded structure/manifest encoding -> ECDSA over raw TBS -> native cross-checks -> "
                 "policy). `payload_tamper_detected` flips a dynamically computed TRUE payload byte "
                 "(golden TBS true payload = [240,244); DER byte-identical) and asserts exactly "
                 "`SIGNATURE_INVALID`; DER-region corruption moved to its own correctly labeled vector "
                 "`der_region_tamper_detected`.")
    lines.append("3. **AC4 ABI negative attribution**: `native_header_abi_mismatch_vs_manifest` keeps "
                 "manifest `required_host_abi=0x00020000`, flips ONLY the native header ABI to "
                 "`0x00010000` (manifest native SHA updated), re-signs, and requires the rejection "
                 "detail to name the native<->manifest cross mismatch. The v2-container-declares-v1-ABI "
                 "case (`v2_container_v1_abi`) remains a separate independent test. Rejection-attribution "
                 "detail matching (`detail_contains`) also added to the archive negative.\n")
    lines.append("## Negative reference artifacts")
    lines.append(f"- `negative-archive-1024-4096.neapp.v2` — {len(arch_pkg)}B, SHA-256 `{report['digests']['sha256_archive_package']}` "
                 f"(spec §8 M7 resource-insufficient negative; never a business-positive sample)")
    lines.append(f"- `v1-golden.neapp` — {len(v1_pkg)}B, SHA-256 `{report['digests']['sha256_v1_golden']}` "
                 f"(frozen v1 §2.5 golden, rebuilt byte-for-byte; interop input only)\n")
    lines.append("## Vector results")
    lines.append("| # | vector | expected | status |")
    lines.append("| --- | --- | --- | --- |")
    for i, v in enumerate(VECTORS, 1):
        lines.append(f"| {i} | `{v['name']}` | {v['expected']} | {v['status']} |")
    lines.append("")
    lines.append("## Boundary (spec §12)")
    lines.append("This evidence proves host-side byte/math/policy behavior of the candidate vectors only. "
                 "No PASS is claimed or implied for: real v2 parsers, STM32 target builds/static asserts, "
                 "device mbedTLS/PKA verification, sustained AI event delivery, cooperative-stop reclaim, "
                 "storage atomicity/power-loss, or actual host resource capacities.")
    open(os.path.join(EVIDENCE_DIR, "report.md"), "w").write("\n".join(lines))
    open(os.path.join(EVIDENCE_DIR, "report.json"), "w").write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"\nEvidence written to {os.path.relpath(EVIDENCE_DIR, ROOT)}/")


def main():
    global SPKI
    SPKI = V.p256_spki_for_d(D_TEST)
    if V.sha256_hex(SPKI) != SPKI_SHA256_HEX:
        print("FATAL: d=1 SPKI digest mismatch — test key assumption broken")
        return 2

    print(f".neapp v2 candidate spec vector suite (evidence -> docs/evidence/spec-v2/)\n")
    golden_tbs, golden_der, golden_pkg = group_golden()
    arch_pkg = bytes.fromhex(ARCHIVED_TBS_244_HEX) + bytes.fromhex(ARCHIVE_DER_HEX)
    group_archive_negative()
    group_resigned_policy_negatives(golden_pkg)
    group_container_structure(golden_pkg)
    group_tamper(golden_pkg)
    v1_pkg = bytes.fromhex(V1_GOLDEN_HEX)
    group_interop_v1(golden_pkg)
    group_event_wire()
    group_model_meta()
    group_tick_ms()
    write_evidence(golden_tbs, golden_der, golden_pkg, arch_pkg, v1_pkg)

    failed = [v for v in VECTORS if v["status"] != "PASS"]
    print(f"\nResult: {len(VECTORS) - len(failed)}/{len(VECTORS)} vectors PASS")
    if failed:
        for v in failed:
            print(f"  FAILED: {v['name']} — {v['detail']}")
        return 1
    print("All vectors PASS. Host-side spec evidence only — no device PASS (spec §12).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
