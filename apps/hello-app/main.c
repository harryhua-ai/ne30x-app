/*
 * hello-app — first standalone NE301 app-host PoC application.
 *
 * Consumes ONLY the pinned public Host ABI header (fetched by
 * tools/fetch_abi_header.sh); links no platform code, no libc, no libgcc.
 * Runs on the host caller's stack: no stack/heap setup, no globals that
 * need initialization, no interrupts, no constructors.
 *
 * Build variants (P3 packaging, Issue #6): HELLO_APP_VERSION selects the
 * independently built V1/V2 image identities.  The default (1) keeps the
 * exact Issue #2 V1 semantics and bytes; version 2 mirrors the historical
 * v2 single-point change (distinct banner, success code 0x4E46 "NF") as a
 * NEW experimental build — it is NOT a byte reproduction of the historical
 * v2 image recorded in docs/evidence/device-evidence.md.
 *
 * Behaviour (mirrors the reference semantics of ne301 experiment
 * app-host-poc@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e
 * tests/app_host/testapp/main.c):
 *   -1  api table pointer is NULL
 *   -2  api->table_size smaller than app_host_api_table_t
 *   -3  abi_version does not EXACTLY equal APP_HOST_ABI_VERSION
 *   -4  api->log or api->tick_ms is NULL
 *   -5  first tick_ms() returned a negative value
 *   -6  second tick_ms() returned a negative value
 *   -7  platform tick went backwards (not monotonic)
 *    V1: 0x4E45 ("NE") — success; see docs/app-hello-poc.md
 *    V2: 0x4E46 ("NF") — success (distinguishable replacement identity)
 */
#include "app_host_abi.h"

#ifndef HELLO_APP_VERSION
#define HELLO_APP_VERSION 1
#endif

#if HELLO_APP_VERSION >= 2
#define HELLO_APP_EXIT_OK 0x4E46u /* "NF" — v2 replacement identity */
#else
#define HELLO_APP_EXIT_OK 0x4E45u /* "NE" */
#endif

/* Busy-wait length: several milliseconds even at the N6 top clock, so the
 * 1 ms platform tick is guaranteed to advance between the two reads. */
#define HELLO_APP_BUSY_LOOPS 2000000u

static void busy_wait(volatile uint32_t loops)
{
    while (loops != 0u) {
        loops--;
    }
}

/* Minimal unsigned 32-bit to decimal converter (no libc, no division:
 * repeated subtraction against a constant power-of-ten table kept in
 * .rodata). Returns the position just past the last digit written. */
static char *u32_to_dec(uint32_t value, char *out)
{
    static const uint32_t pow10[10] = {
        1000000000u, 100000000u, 10000000u, 1000000u, 100000u,
        10000u, 1000u, 100u, 10u, 1u
    };
    uint32_t i;
    uint32_t started = 0u;
    for (i = 0u; i < 10u; i++) {
        uint32_t digit = 0u;
        while (value >= pow10[i]) {
            value -= pow10[i];
            digit++;
        }
        if ((digit != 0u) || (started != 0u) || (i == 9u)) {
            *out++ = (char)('0' + (int)digit);
        }
        if (digit != 0u) {
            started = 1u;
        }
    }
    return out;
}

static char *append_str(char *out, const char *s)
{
    while (*s != '\0') {
        *out++ = *s++;
    }
    return out;
}

int app_entry(const app_host_api_table_t *api, uint32_t abi_version)
{
    int t1;
    int t2;
    char line[80];
    char *p;

    if (api == (void *)0) {
        return -1;
    }
    if (api->table_size < (uint32_t)sizeof(app_host_api_table_t)) {
        return -2;
    }
    if (abi_version != APP_HOST_ABI_VERSION) {
        return -3;
    }
    if ((api->log == (void *)0) || (api->tick_ms == (void *)0)) {
        return -4;
    }

#if HELLO_APP_VERSION >= 2
    api->log("hello-app v2: standalone NE301 app PoC, ABI v1.0");
#else
    api->log("hello-app: standalone NE301 app PoC, ABI v1.0");
#endif

    t1 = api->tick_ms();
    if (t1 < 0) {
        return -5;
    }
    busy_wait(HELLO_APP_BUSY_LOOPS);
    t2 = api->tick_ms();
    if (t2 < 0) {
        return -6;
    }
    if ((uint32_t)t2 < (uint32_t)t1) {
        return -7;
    }

    p = append_str(line, "hello-app: tick_ms t1=");
    p = u32_to_dec((uint32_t)t1, p);
    p = append_str(p, " t2=");
    p = u32_to_dec((uint32_t)t2, p);
    p = append_str(p, " delta=");
    p = u32_to_dec((uint32_t)t2 - (uint32_t)t1, p);
    *p = '\0';
    api->log(line);

    if ((uint32_t)t2 > (uint32_t)t1) {
        api->log("hello-app: platform clock advanced, host APIs usable");
    } else {
        api->log("hello-app: platform clock did not advance within the busy wait");
    }

    return (int)HELLO_APP_EXIT_OK;
}
