/*
 * fs_manifest — read-only LittleFS content manifest for device-evidence (Issue #2, AC3).
 *
 * Purpose: independently prove the content-level invariant "pristine backup data
 * preserved, only test files added" by listing every file in a LittleFS image
 * with path | size | SHA256(content).
 *
 * The input image is opened read-only and is NEVER modified (no out image, no
 * in-place mutation): the whole volume is read into RAM once, mounted read-only,
 * and walked recursively. sha256 is computed streaming over lfs_file_read output
 * (logical file content, not raw blocks).
 *
 * Geometry matches the device LittleFS exactly:
 *   block_size     = 4096            (pinned Custom/Hal/storage.h:18 FLASH_BLOCK_SIZE)
 *   read/prog/cache= 1024            (pinned Custom/Hal/storage.h:26 FS_LFS_CACHE_SIZE,
 *                                      Custom/Hal/storage.c:488-493)
 *   block_count    = image_size/4096 (96MB volume -> 24576 blocks)
 *   lookahead_size = 3072            (LITTLEFS_SIZE/FLASH_BLOCK_SIZE/8, storage.h:31)
 *   block_cycles   = 10000           (write-time knob only; no effect on read)
 * read/prog/cache sizes do not affect the littlefs on-flash layout; only
 * block_size does, and it equals the device value.
 *
 * Volume base/length on device (pinned Custom/Common/Inc/mem_map.h:108-113):
 *   LITTLEFS 0x71D00000 .. 0x77CFFFFF, 96M (128M-board build).
 *
 * Build (macOS/arm64 host, same littlefs sources the PoC lfstool used):
 *   cc -O2 -Wall -I /tmp/ne301-host-build/Custom/Common/Lib/littlefs \
 *      -o /tmp/fs_manifest tools/fs_manifest.c \
 *      /tmp/ne301-host-build/Custom/Common/Lib/littlefs/lfs.c \
 *      /tmp/ne301-host-build/Custom/Common/Lib/littlefs/lfs_util.c
 *
 * Usage:
 *   fs_manifest <image.bin> <image_path_label>
 * Output (stdout), sorted by path for deterministic diffing:
 *   path|size|sha256   per file, then "# totals files=N dirs=D bytes=B"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include "lfs.h"

/* ---------------- minimal SHA-256 (FIPS 180-4) ---------------- */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t buf_len;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len = 0; c->buf_len = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64], a,b,cc,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15],7)^ROTR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = ROTR(w[i-2],17)^ROTR(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e,6)^ROTR(e,11)^ROTR(e,25);
        uint32_t ch = (e&f)^((~e)&g);
        t1 = h+S1+ch+K[i]+w[i];
        uint32_t S0 = ROTR(a,2)^ROTR(a,13)^ROTR(a,22);
        uint32_t maj = (a&b)^(a&cc)^(b&cc);
        t2 = S0+maj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n) {
    const uint8_t *p = data;
    c->len += n;
    while (n > 0) {
        size_t take = 64 - c->buf_len;
        if (take > n) take = n;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take; p += take; n -= take;
        if (c->buf_len == 64) { sha256_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buf_len != 56) sha256_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

static void sha256_hex(const uint8_t d[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i*2]   = hex[d[i] >> 4];
        out[i*2+1] = hex[d[i] & 15];
    }
    out[64] = 0;
}

/* ---------------- read-only block device over in-RAM image ---------------- */

static uint8_t *g_img;
static size_t g_size;

static int bd_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size) {
    (void)c;
    memcpy(buffer, g_img + (size_t)block * 4096 + off, size);
    return 0;
}
static int bd_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size) {
    (void)c; (void)block; (void)off; (void)buffer; (void)size;
    return LFS_ERR_IO; /* read-only tool: any prog attempt is a hard error */
}
static int bd_erase(const struct lfs_config *c, lfs_block_t block) {
    (void)c; (void)block;
    return LFS_ERR_IO;
}
static int bd_sync(const struct lfs_config *c) { (void)c; return 0; }

/* ---------------- recursive walk ---------------- */

#define MAX_PATH 512

static int g_files, g_dirs, g_missing;
static uint64_t g_bytes;

static void walk(lfs_t *lfs, const char *dirpath) {
    lfs_dir_t dir;
    struct lfs_info info;
    if (lfs_dir_open(lfs, &dir, dirpath) != 0) {
        fprintf(stderr, "fs_manifest: dir open failed: %s\n", dirpath);
        g_missing++;
        return;
    }
    while (lfs_dir_read(lfs, &dir, &info) > 0) {
        if (!strcmp(info.name, ".") || !strcmp(info.name, "..")) continue;
        char sub[MAX_PATH];
        if (snprintf(sub, sizeof(sub), "%s%s%s", dirpath,
                     strcmp(dirpath, "/") == 0 ? "" : "/", info.name) >= (int)sizeof(sub)) {
            fprintf(stderr, "fs_manifest: path too long: %s/%s\n", dirpath, info.name);
            g_missing++;
            continue;
        }
        if (info.type == LFS_TYPE_DIR) {
            g_dirs++;
            walk(lfs, sub);
        } else {
            lfs_file_t fp;
            if (lfs_file_open(lfs, &fp, sub, LFS_O_RDONLY) != 0) {
                fprintf(stderr, "fs_manifest: file open failed: %s\n", sub);
                g_missing++;
                continue;
            }
            sha256_ctx c;
            sha256_init(&c);
            static uint8_t buf[8192];
            lfs_ssize_t n;
            uint64_t total = 0;
            while ((n = lfs_file_read(lfs, &fp, buf, sizeof(buf))) > 0) {
                sha256_update(&c, buf, (size_t)n);
                total += (uint64_t)n;
            }
            lfs_file_close(lfs, &fp);
            if (n < 0) {
                fprintf(stderr, "fs_manifest: read error %s: %d\n", sub, (int)n);
                g_missing++;
                continue;
            }
            uint8_t d[32]; char hex[65];
            sha256_final(&c, d); sha256_hex(d, hex);
            printf("%s|%llu|%s\n", sub, (unsigned long long)total, hex);
            g_files++; g_bytes += total;
        }
    }
    lfs_dir_close(lfs, &dir);
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <image.bin> <image_path_label>\n", argv[0]);
        return 2;
    }
    const char *img_path = argv[1];
    const char *img_label = argv[2];

    FILE *f = fopen(img_path, "rb");
    if (!f) { perror("fs_manifest: open image"); return 1; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("seek"); return 1; }
    long sz = ftell(f);
    if (sz <= 0) { fprintf(stderr, "fs_manifest: empty image\n"); return 1; }
    g_size = (size_t)sz;
    rewind(f);
    g_img = malloc(g_size);
    if (!g_img || fread(g_img, 1, g_size, f) != g_size) {
        fprintf(stderr, "fs_manifest: read image failed\n"); return 1;
    }
    fclose(f);

    /* image-level sha256 for self-identification of the manifest */
    sha256_ctx ic; sha256_init(&ic);
    sha256_update(&ic, g_img, g_size);
    uint8_t id[32]; char ihex[65];
    sha256_final(&ic, id); sha256_hex(id, ihex);

    struct lfs_config cfg = {0};
    cfg.read = bd_read; cfg.prog = bd_prog; cfg.erase = bd_erase; cfg.sync = bd_sync;
    cfg.read_size = 1024; cfg.prog_size = 1024; cfg.block_size = 4096;
    cfg.block_count = (lfs_size_t)(g_size / 4096);
    cfg.block_cycles = 10000;
    cfg.cache_size = 1024; cfg.lookahead_size = 3072;

    lfs_t lfs;
    int err = lfs_mount(&lfs, &cfg);
    if (err) { fprintf(stderr, "fs_manifest: mount failed: %d\n", err); return 1; }

    char ts[32] = "?";
    time_t now = time(NULL);
    struct tm tmv;
    if (gmtime_r(&now, &tmv)) strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);

    /* Collect lines first so output can be sorted deterministically. */
    /* Simple approach: walk into a temp stream via stdout redirect is messy;
       instead walk directly but pre-sort by reading dir tree into memory of paths. */
    /* Use tmpfile buffer to hold the listing, then sort lines with qsort. */
    FILE *tmp = tmpfile();
    if (!tmp) { fprintf(stderr, "fs_manifest: tmpfile failed\n"); return 1; }
    int out_fd_backup = dup(1);
    fflush(stdout);
    dup2(fileno(tmp), 1);

    walk(&lfs, "/");

    fflush(stdout);
    dup2(out_fd_backup, 1);
    close(out_fd_backup);

    err = lfs_unmount(&lfs);
    if (err) { fprintf(stderr, "fs_manifest: unmount: %d\n", err); return 1; }
    free(g_img);

    /* read back, sort, print */
    long tlen = ftell(tmp);
    rewind(tmp);
    char *data = malloc((size_t)tlen + 1);
    if (!data || fread(data, 1, (size_t)tlen, tmp) != (size_t)tlen) {
        fprintf(stderr, "fs_manifest: reread tmp failed\n"); return 1;
    }
    fclose(tmp);

    size_t nlines = 0;
    for (long i = 0; i < tlen; i++) if (data[i] == '\n') nlines++;
    char **lines = calloc(nlines ? nlines : 1, sizeof(char *));
    size_t li = 0, start = 0;
    for (long i = 0; i <= tlen; i++) {
        if (i == tlen || data[i] == '\n') {
            if (i > start) lines[li++] = data + start;
            data[i == tlen ? tlen : i] = 0; /* safe: i==tlen case writes the NUL we allocated (+1) */
            start = i + 1;
            if (i == tlen) break;
        }
    }
    qsort(lines, li, sizeof(char *), cmp_str);
    for (size_t i = 0; i < li; i++) printf("%s\n", lines[i]);

    fprintf(stderr, "fs_manifest: image=%s label=%s sha256=%s files=%d dirs=%d bytes=%llu unreadable=%d\n",
            img_path, img_label, ihex, g_files, g_dirs, (unsigned long long)g_bytes, g_missing);
    printf("# fs_manifest v1 generated=%s\n", ts);
    printf("# image_label=%s\n", img_label);
    printf("# image_size=%zu\n", g_size);
    printf("# image_sha256=%s\n", ihex);
    printf("# geometry: block_size=4096 read=1024 prog=1024 cache=1024 lookahead=3072 (device-exact, pinned storage.h/storage.c)\n");
    printf("# totals files=%d dirs=%d bytes=%llu unreadable=%d\n",
           g_files, g_dirs, (unsigned long long)g_bytes, g_missing);
    if (g_missing != 0) {
        fprintf(stderr, "fs_manifest: %d entries could not be read — manifest incomplete\n", g_missing);
        return 3;
    }
    return 0;
}
