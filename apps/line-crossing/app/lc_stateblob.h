/*
 * lc_stateblob.h — the App-owned persistent business state blob.
 *
 * The v2 Host stores ONE opaque blob per App identity (spec §6.7) via
 * state_read/state_commit with expected_revision atomicity; the App owns
 * the internal schema.  The layout here is explicit little-endian,
 * field-by-field (no struct padding), with a CRC-32 over the payload, so
 * corruption is detectable rather than silently consumed.
 *
 * What persists (counting-parity + Issue #11 AC3): business config,
 * cumulative and window counters, and the report sequence identity.
 * Session-scoped things (tick-domain window start, track IDs) do NOT.
 */
#ifndef LC_STATEBLOB_H
#define LC_STATEBLOB_H

#include <stdint.h>
#include "lc_bus_config.h"

#define LC_ST_BLOB_MAGIC        0x5341434Cu /* "LCAS" (LE byte order) */
#define LC_ST_BLOB_SCHEMA       1u
#define LC_ST_BLOB_MAX          512u

/* returns the serialized length; 0 on encode error (never partial) */
uint32_t lc_st_encode(uint8_t *out, uint32_t cap, const lc_bus_config_t *cfg,
                      uint32_t total_in, uint32_t total_out,
                      uint32_t window_in, uint32_t window_out,
                      uint32_t report_seq);

typedef enum {
    LC_ST_OK = 0,
    LC_ST_ERR_SIZE = 1,
    LC_ST_ERR_MAGIC = 2,
    LC_ST_ERR_SCHEMA = 3,
    LC_ST_ERR_CRC = 4,
    LC_ST_ERR_CONTENT = 5
} lc_st_status_t;

lc_st_status_t lc_st_decode(const uint8_t *in, uint32_t len,
                            lc_bus_config_t *cfg,
                            uint32_t *total_in, uint32_t *total_out,
                            uint32_t *window_in, uint32_t *window_out,
                            uint32_t *report_seq);

#endif
