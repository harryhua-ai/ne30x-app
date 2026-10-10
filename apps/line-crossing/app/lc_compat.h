/*
 * lc_compat.h — minimal string helpers with one implementation seam.
 *
 * Host (tests, core regression): thin wrappers over <string.h>.
 * Target (native v2 image): the app is linked -nostdlib -ffreestanding;
 * these wrappers call the small local definitions in lc_libc_mini.c, which
 * also provides the memcpy/memset/... symbols the compiler may emit for
 * struct copies.  No stdio, no heap libc, no locale anywhere.
 */
#ifndef LC_COMPAT_H
#define LC_COMPAT_H

#include <stddef.h>

#ifdef LC_APP_TARGET

void *lc_memcpy(void *dst, const void *src, size_t n);
void *lc_memset(void *dst, int c, size_t n);
int   lc_memcmp(const void *a, const void *b, size_t n);
size_t lc_strlen(const char *s);
int   lc_strcmp(const char *a, const char *b);
int   lc_strncmp(const char *a, const char *b, size_t n);
/* bounded copy, always NUL-terminates (n > 0); returns src length */
size_t lc_strlcpy(char *dst, const char *src, size_t n);

#else /* host */

#include <string.h>
static inline void *lc_memcpy(void *dst, const void *src, size_t n) { return memcpy(dst, src, n); }
static inline void *lc_memset(void *dst, int c, size_t n) { return memset(dst, c, n); }
static inline int   lc_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static inline size_t lc_strlen(const char *s) { return strlen(s); }
static inline int   lc_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static inline int   lc_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
static inline size_t lc_strlcpy(char *dst, const char *src, size_t n)
{
    size_t l = strlen(src);
    if (n == 0) return l;
    size_t c = (l < n - 1u) ? l : n - 1u;
    memcpy(dst, src, c);
    dst[c] = '\0';
    return l;
}

#endif
#endif
