/*
 * test_common.h — minimal check/count harness shared by the App test bins.
 */
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int g_pass;
extern int g_fail;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (cond) {                                                        \
            g_pass++;                                                      \
        } else {                                                           \
            g_fail++;                                                      \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
        }                                                                  \
    } while (0)

#define CHECK_EQ_I(a, b)                                                   \
    do {                                                                   \
        long long _a = (long long)(a), _b = (long long)(b);                \
        if (_a == _b) {                                                    \
            g_pass++;                                                      \
        } else {                                                           \
            g_fail++;                                                      \
            printf("  FAIL %s:%d: %s == %s (%lld != %lld)\n",              \
                   __FILE__, __LINE__, #a, #b, _a, _b);                    \
        }                                                                  \
    } while (0)

#define TEST_REPORT(name)                                                  \
    do {                                                                   \
        printf("[%s] pass=%d fail=%d -> %s\n", (name), g_pass, g_fail,     \
               g_fail == 0 ? "PASS" : "FAIL");                             \
        return g_fail == 0 ? 0 : 1;                                        \
    } while (0)

#endif
