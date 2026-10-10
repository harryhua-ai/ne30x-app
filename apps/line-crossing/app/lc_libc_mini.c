/*
 * lc_libc_mini.c — freestanding string primitives for the native v2 image.
 *
 * Compiled ONLY into the target build (-nostdlib -ffreestanding).  Besides
 * the lc_* wrappers it defines the ISO names the compiler is allowed to
 * emit calls to for struct assignment / initialization even under
 * -fno-builtin (memcpy, memmove, memset, strlen...), so the link never
 * pulls in a host libc.
 */
#include <stddef.h>

typedef unsigned long lc_word;

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    /* word copies keep image size and speed sane; alignment checked per byte */
    while (n && ((lc_word)d & (sizeof(lc_word) - 1u))) { *d++ = *s++; n--; }
    while (n >= sizeof(lc_word) * 4u) {
        lc_word w0, w1, w2, w3;
        __builtin_memcpy(&w0, s, sizeof(lc_word));
        __builtin_memcpy(&w1, s + sizeof(lc_word), sizeof(lc_word));
        __builtin_memcpy(&w2, s + 2 * sizeof(lc_word), sizeof(lc_word));
        __builtin_memcpy(&w3, s + 3 * sizeof(lc_word), sizeof(lc_word));
        __builtin_memcpy(d, &w0, sizeof(lc_word));
        __builtin_memcpy(d + sizeof(lc_word), &w1, sizeof(lc_word));
        __builtin_memcpy(d + 2 * sizeof(lc_word), &w2, sizeof(lc_word));
        __builtin_memcpy(d + 3 * sizeof(lc_word), &w3, sizeof(lc_word));
        s += sizeof(lc_word) * 4u; d += sizeof(lc_word) * 4u; n -= sizeof(lc_word) * 4u;
    }
    while (n >= sizeof(lc_word)) {
        lc_word w; __builtin_memcpy(&w, s, sizeof(lc_word));
        __builtin_memcpy(d, &w, sizeof(lc_word));
        s += sizeof(lc_word); d += sizeof(lc_word); n -= sizeof(lc_word);
    }
    while (n) { *d++ = *s++; n--; }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) return dst;
    if ((lc_word)s < (lc_word)d && (lc_word)s + n > (lc_word)d) {
        d += n; s += n;
        while (n) { *--d = *--s; n--; }
        return dst;
    }
    return memcpy(dst, src, n);
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    unsigned char b = (unsigned char)c;
    while (n && ((lc_word)d & (sizeof(lc_word) - 1u))) { *d++ = b; n--; }
    if (n >= sizeof(lc_word)) {
        lc_word w = 0;
        for (size_t i = 0; i < sizeof(lc_word); i++) ((unsigned char *)&w)[i] = b;
        while (n >= sizeof(lc_word)) {
            __builtin_memcpy(d, &w, sizeof(lc_word));
            d += sizeof(lc_word); n -= sizeof(lc_word);
        }
    }
    while (n) { *d++ = b; n--; }
    return dst;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n) {
        if (*x != *y) return (int)*x - (int)*y;
        x++; y++; n--;
    }
    return 0;
}

/* ---- lc_compat.h wrappers (target build) ---- */
#include "lc_compat.h"

/* ---- sqrtf: the lc core uses sqrtf for match distance / line length ----
 * Newlib's sqrtf drags in __errno; the freestanding image instead uses the
 * Cortex-M55 FPU's IEEE-754 correctly-rounded VSQRT.F32 directly (same
 * numerics as the host libm for the finite non-negative inputs the core
 * feeds it).  Negative/NaN inputs return 0.0f — unreachable in the core,
 * which only squares differences. */
float sqrtf(float x)
{
#if defined(__arm__) || defined(__thumb__)
    float r;
    if (!(x > 0.0f)) return 0.0f;
    __asm__ volatile ("vsqrt.f32 %0, %1" : "=t" (r) : "t" (x));
    return r;
#else
    float r = x;
    if (!(x > 0.0f)) return 0.0f;
    /* Newton-Raphson fallback (non-ARM targets only) */
    union { float f; unsigned int u; } v;
    v.f = x;
    v.u = 0x5f3759dfu - (v.u >> 1);
    r = v.f;
    r = r * (1.5f - 0.5f * x * r * r);
    r = r * (1.5f - 0.5f * x * r * r);
    return r * x;
#endif
}

void *lc_memcpy(void *dst, const void *src, size_t n) { return memcpy(dst, src, n); }
void *lc_memset(void *dst, int c, size_t n) { return memset(dst, c, n); }
int   lc_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
size_t lc_strlen(const char *s) { return strlen(s); }
int   lc_strcmp(const char *a, const char *b) { return strcmp(a, b); }
int   lc_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
size_t lc_strlcpy(char *dst, const char *src, size_t n)
{
    size_t l = strlen(src);
    if (n == 0) return l;
    size_t c = (l < n - 1u) ? l : n - 1u;
    memcpy(dst, src, c);
    dst[c] = '\0';
    return l;
}
