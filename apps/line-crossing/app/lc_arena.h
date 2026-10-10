/*
 * lc_arena.h — tiny first-fit free-list allocator over a static arena.
 *
 * The ported lc_* core allocates its tracker and per-frame archive records
 * through the LC_MALLOC/LC_FREE seam (apps/line-crossing/include/lc_types.h).
 * On the native v2 image there is no libc heap, so the app links that seam
 * to this allocator (see the target Makefile: -DLC_MALLOC(sz)=lcapp_alloc(sz)
 * -DLC_FREE(p)=lcapp_free(p)).  The arena is zero-initialized .bss; the host
 * test build exercises the exact same allocator through its unit tests and
 * via LC_TEST_ARENA Injection.
 */
#ifndef LC_ARENA_H
#define LC_ARENA_H

#include <stddef.h>
#include <stdint.h>

#define LC_ARENA_SIZE (96u * 1024u) /* tracker (64 tracks) + transient records */

void  lcapp_arena_init(void);            /* idempotent; resets the arena      */
void *lcapp_alloc(size_t sz);             /* NULL when exhausted (fail-closed) */
void  lcapp_free(void *p);
size_t lcapp_arena_used(void);
size_t lcapp_arena_high_water(void);

#endif
