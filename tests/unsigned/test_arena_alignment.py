from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "apps" / "line-crossing" / "app"
ARENA_SRC = APP / "lc_arena.c"
ELF = APP / "build" / "lc-line-crossing-v4.elf"

DRIVER = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "lc_arena.c"

#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); return 1; } } while (0)

int main(void)
{
    CHECK(((uintptr_t)lc_arena_pool % 8u) == 0u);
    size_t full = lcapp_arena_high_water();
    void *a = lcapp_alloc(1u);
    CHECK(a != NULL);
    CHECK(((uintptr_t)a % 8u) == 0u);
    memset(a, 0xA5, 1u);
    void *b = lcapp_alloc(300u);
    CHECK(b != NULL);
    CHECK(((uintptr_t)b % 8u) == 0u);
    CHECK(((uintptr_t)b - (uintptr_t)a) >= 8u + 8u);
    memset(b, 0x5A, 300u);
    lcapp_free(a);
    void *c = lcapp_alloc(8u);
    CHECK(c == a);
    lcapp_free(c);
    lcapp_free(b);
    CHECK(lcapp_arena_used() == 0u);
    void *big = lcapp_alloc(96u * 1024u - 16u);
    CHECK(big != NULL);
    CHECK(((uintptr_t)big % 8u) == 0u);
    memset(big, 0xC3, 96u * 1024u - 16u);
    CHECK(lcapp_alloc(8u) == NULL);
    lcapp_free(big);
    CHECK(lcapp_arena_used() == 0u);
    CHECK(lcapp_arena_high_water() >= full);
    printf("PASS arena host functional\n");
    return 0;
}
"""

class TestArenaAlignment(unittest.TestCase):
    def test_pool_symbol_8_byte_aligned_in_real_arm_elf(self):
        r = subprocess.run(
            ["make", "-C", str(APP), "elf-v4", "V4_APP_VERSION=4.0.0"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, f"elf-v4 build failed: {r.stderr[-800:]}")
        self.assertTrue(ELF.exists(), "real v4 ELF was not built")
        out = subprocess.run(
            ["arm-none-eabi-nm", str(ELF)],
            check=True, capture_output=True, text=True,
        ).stdout
        m = re.search(r"^([0-9a-fA-F]+)\s+b\s+lc_arena_pool$", out, re.M)
        self.assertIsNotNone(m, "lc_arena_pool symbol not found in real ELF")
        addr = int(m.group(1), 16)
        self.assertEqual(
            addr % 8, 0,
            f"lc_arena_pool at 0x{addr:x} is not 8-byte aligned; "
            "block headers would be cast onto unaligned addresses "
            "(regression of NE301 #48 defect 8)",
        )

    def test_allocator_functional_on_host(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / "arena_host"
            r = subprocess.run(
                ["cc", "-x", "c", "-std=gnu11", "-I", str(APP), "-", "-o", str(exe)],
                input=DRIVER, capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, f"host build failed: {r.stderr}")
            out = subprocess.run([str(exe)], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("PASS arena host functional", out.stdout)


if __name__ == "__main__":
    unittest.main()
