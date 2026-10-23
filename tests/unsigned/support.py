from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package"))
sys.path.insert(0, str(ROOT / "package" / "sidecar"))
sys.path.insert(0, str(ROOT / "package" / "unsigned"))
sys.path.insert(0, str(ROOT / "package" / "vnext"))

import neapp_v4_format as v4
from neapp_v4_image import ELF_HEADER, ELF_PROGRAM_HEADER

FIXTURE_APP_ID = "line-crossing"
FIXTURE_NATIVE_VERSION = (4, 0, 0)
FIXTURE_UI_VERSION = (1, 0, 0)
FIXTURE_MARKER = b"line-crossing-app 4.0.0: v4 session entry"
FIXTURE_ASSETS = (
    ("index.html", b"<!doctype html><title>line-crossing</title><p>fixture</p>\n"),
    ("app.js", b"console.log('line-crossing fixture');\n"),
    ("assets/logo.txt", b"NE30x line-crossing fixture asset\n"),
)
FIXTURE_PACKAGE_PATH = ROOT / "tests" / "fixtures" / "line-crossing-4.0.0.neapp"


def fixture_elf(marker: bytes = FIXTURE_MARKER, base: int = v4.EXEC_BASE_V4) -> bytes:
    phnum = 1
    headers_end = ELF_HEADER.size + phnum * ELF_PROGRAM_HEADER.size
    first_offset = (headers_end + 15) & ~15
    file_len = first_offset + len(marker)
    out = bytearray(file_len)
    ident = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    ELF_HEADER.pack_into(out, 0, ident, 2, 40, 1, base + 1, ELF_HEADER.size, 0, 0,
                         ELF_HEADER.size, ELF_PROGRAM_HEADER.size, phnum, 0, 0, 0)
    ELF_PROGRAM_HEADER.pack_into(out, ELF_HEADER.size, 1, first_offset, base, base,
                                 len(marker), len(marker), 5, 4)
    out[first_offset:first_offset + len(marker)] = marker
    return bytes(out)


def write_fixture_ui_tree(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, blob in FIXTURE_ASSETS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    return root


def pack_fixture(elf_path: Path, ui_root: Path, output_path: Path,
                 provenance_path: Path | None = None) -> dict:
    from neapp_pack_v5 import build_v5
    return build_v5(
        elf_path, ui_root, output_path, FIXTURE_APP_ID,
        FIXTURE_NATIVE_VERSION, FIXTURE_UI_VERSION,
        v4.CAP_LOG | v4.CAP_TICK_MS | v4.CAP_SESSION_LIFECYCLE | v4.CAP_CONTROL_RECEIVE,
        0, 0, 0, 256, 0, 0, 0, None,
        source_commit="fixture",
        provenance_path=provenance_path,
    )


def fixture_package_sha256() -> str:
    return hashlib.sha256(FIXTURE_PACKAGE_PATH.read_bytes()).hexdigest()
