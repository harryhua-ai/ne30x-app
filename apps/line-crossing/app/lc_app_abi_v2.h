/*
 * lc_app_abi_v2.h — the frozen Host ABI v2 surface consumed by the
 * Line Crossing App (Harry Dev Issue #11).
 *
 * Single authority for every constant in this header is the integrated
 * v2 protocol spec: docs/app-package-protocol-v2-draft.md (Issue #12
 * baseline), in particular:
 *   §5  AI event wire (40B header + 24B detection records, <=64 records)
 *   §6.1/§6.2  ABI 0x00020000, app_entry signature, exactly-48B function
 *              table with 10 fixed Thumb function pointers (offsets 8..44)
 *   §6.3  pinned C signatures for all ten functions
 *   §6.4  fixed return-code enum (0/1/2 and -1..-10); tick_ms is the ONLY
 *         exception: its return value is the raw 32-bit monotonic-ms bit
 *         pattern and must be compared modulo 2^32, never read as an error
 *   §6.5  128B model_meta layout, generation-bound class_name queries
 *   §6.6  report_submit / report_status semantics and channel enums
 *   §6.7  state_read / state_commit expected_revision semantics
 *   §6.8  should_stop cooperative-stop semantics
 *
 * No field, offset or code here may be invented or renumbered; anything the
 * spec does not define is rejected fail-closed by the consumer (lc_bus.c).
 *
 * Cross-ABI structure rule (§6.2): fixed-width integers / byte arrays /
 * float bits only; sizeof(void*)==4; the layout static asserts are
 * mandatory on the 32-bit target build and are compiled wherever they can
 * hold (host test builds on 64-bit hosts skip only the pointer-width
 * asserts; the wire is parsed through explicit little-endian byte loads so
 * host and target share one parser).
 */
#ifndef LC_APP_ABI_V2_H
#define LC_APP_ABI_V2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- §6.1 ABI version and entry ------------------------------------- */

#define LC_APP_ABI_V2 0x00020000u

/* app_entry: int32_t app_entry(const lc_app_api_v2_t *api, uint32_t abi_version)
 * (declared in lc_app_entry.h; defined by lc_app_entry.c) */

/* ---- §6.2 the exactly-48B v2 function table -------------------------- */

#define LC_APP_API_TABLE_SIZE 48u

typedef int32_t (*lc_app_fn_log_t)(const char *text);
typedef int32_t (*lc_app_fn_tick_ms_t)(void);
typedef int32_t (*lc_app_fn_event_next_t)(void *out, uint32_t cap,
                                          uint32_t *actual_len,
                                          uint32_t max_wait_ms);
typedef int32_t (*lc_app_fn_model_meta_t)(void *out, uint32_t cap,
                                          uint32_t *actual_len);
typedef int32_t (*lc_app_fn_class_name_t)(uint32_t model_gen,
                                          uint32_t class_gen,
                                          uint32_t class_index,
                                          void *out_utf8, uint32_t cap,
                                          uint32_t *actual_len);
typedef int32_t (*lc_app_fn_report_submit_t)(const void *json, uint32_t len,
                                             uint32_t app_report_seq,
                                             uint32_t *out_host_boot_id);
typedef int32_t (*lc_app_fn_report_status_t)(uint32_t host_boot_id,
                                             uint32_t report_seq,
                                             uint32_t *out_mqtt_state,
                                             uint32_t *out_webhook_state);
typedef int32_t (*lc_app_fn_state_read_t)(void *out, uint32_t cap,
                                          uint32_t *actual_len,
                                          uint32_t *out_revision);
typedef int32_t (*lc_app_fn_state_commit_t)(const void *blob, uint32_t len,
                                            uint32_t expected_revision,
                                            uint32_t *new_revision);
typedef int32_t (*lc_app_fn_should_stop_t)(void);

typedef struct lc_app_api_v2 {
    uint32_t                 table_size;   /* offset 0:  must be 48        */
    uint32_t                 abi_version;  /* offset 4:  must be 0x00020000 */
    lc_app_fn_log_t          log;          /* offset 8                     */
    lc_app_fn_tick_ms_t      tick_ms;      /* offset 12                    */
    lc_app_fn_event_next_t   event_next;   /* offset 16                    */
    lc_app_fn_model_meta_t   model_meta;   /* offset 20                    */
    lc_app_fn_class_name_t   class_name;   /* offset 24                    */
    lc_app_fn_report_submit_t report_submit; /* offset 28                  */
    lc_app_fn_report_status_t report_status; /* offset 32                  */
    lc_app_fn_state_read_t   state_read;   /* offset 36                    */
    lc_app_fn_state_commit_t state_commit; /* offset 40                    */
    lc_app_fn_should_stop_t  should_stop;  /* offset 44                    */
} lc_app_api_v2_t;

#if UINTPTR_MAX == 0xFFFFFFFFu /* 32-bit target: §6.2 static asserts are mandatory */
#include "lc_app_abi_v2_layout_asserts.h"
#endif

/* ---- §6.4 fixed return-code enum ------------------------------------- */

#define LC_RET_OK               0
#define LC_RET_NO_EVENT         1   /* only event_next                       */
#define LC_RET_NOT_FOUND        2   /* only state_read / report_status       */
#define LC_RET_INVALID_ARGUMENT (-1)
#define LC_RET_BUFFER_TOO_SMALL (-2)
#define LC_RET_UNAUTHORIZED     (-3)
#define LC_RET_INCOMPATIBLE     (-4)
#define LC_RET_QUOTA_EXCEEDED   (-5)
#define LC_RET_STORAGE_UNKNOWN  (-6)
#define LC_RET_BUSY             (-7)
#define LC_RET_REVISION_CONFLICT (-8)
#define LC_RET_IO_ERROR         (-9)
#define LC_RET_STOPPING         (-10)

/* ---- §5 AI event wire ------------------------------------------------- */

#define LC_EVT_KIND_FRAME        1u
#define LC_EVT_KIND_MODEL_CHANGED 2u
#define LC_EVT_KIND_GAP          3u
#define LC_EVT_KIND_STOPPING     4u

#define LC_EVT_FLAG_LOST_KNOWN   0x1u  /* bit0: known/suspected loss       */
#define LC_EVT_FLAG_LOST_UNKNOWN 0x2u  /* bit1: lost_frame_count=0xFFFFFFFF */
#define LC_EVT_FLAGS_VALID_MASK  0x3u  /* bit2..31 must be zero            */

#define LC_EVT_LOST_UNKNOWN_MARK 0xFFFFFFFFu

#define LC_EVT_HDR_SIZE          40u   /* 10 x u32-le                       */
#define LC_EVT_REC_SIZE          24u   /* 6 x u32-le                        */
#define LC_EVT_MAX_DETECTIONS    64u
#define LC_EVT_MAX_SIZE          (LC_EVT_HDR_SIZE + LC_EVT_MAX_DETECTIONS * LC_EVT_REC_SIZE) /* 1576 */

/* event header field indices (x4 bytes) */
#define LC_EVTH_TOTAL_LEN        0u
#define LC_EVTH_KIND             1u
#define LC_EVTH_SEQUENCE         2u
#define LC_EVTH_MONOTONIC_MS     3u
#define LC_EVTH_MODEL_GEN        4u
#define LC_EVTH_CLASS_GEN        5u
#define LC_EVTH_FLAGS            6u
#define LC_EVTH_DETECTION_COUNT  7u
#define LC_EVTH_LOST_FRAME_COUNT 8u
#define LC_EVTH_RESERVED0        9u

/* detection record field indices (x4 bytes) */
#define LC_EVT_REC_X_BITS        0u
#define LC_EVT_REC_Y_BITS        1u
#define LC_EVT_REC_WIDTH_BITS    2u
#define LC_EVT_REC_HEIGHT_BITS   3u
#define LC_EVT_REC_CONF_BITS     4u
#define LC_EVT_REC_CLASS_INDEX   5u

/* ---- §6.5 model metadata (exactly 128B) ------------------------------ */

#define LC_MODEL_META_SIZE       128u
#define LC_MODEL_META_RESULT_OD  1u   /* PP_TYPE_OD: the only supported type */
#define LC_MODEL_NAME_LEN        64u
#define LC_MODEL_VERSION_LEN     32u

/* ---- §6.6 report channel state enums ---------------------------------- */

#define LC_RSTATE_NOT_CONFIGURED     0u
#define LC_RSTATE_PENDING            1u
#define LC_RSTATE_TRANSPORT_SUCCEEDED 2u
#define LC_RSTATE_TRANSPORT_FAILED   3u
#define LC_RSTATE_UNKNOWN            4u

/* ---- §4.1 business capacity floors consumed by this app --------------- */
/* declared quotas this App requires (packaged as caps=0x3f, 2048/4096/6144;
 * a Host that cannot honor them must have refused the session already) */

#define LC_APP_EVENT_BUF_CAP     2048u  /* declared event_max                  */
#define LC_APP_STATE_QUOTA       4096u  /* declared state_quota                */
#define LC_APP_REPORT_MAX        6144u  /* declared report_max (§4.1 floor)    */

/* ---- mod-2^32 helpers (§6.3 tick_ms exception / §5.1 session sequence) - */

static inline uint32_t lc_tick_diff(uint32_t later, uint32_t earlier)
{
    return (uint32_t)(later - earlier); /* defined mod 2^32 */
}

/* explicit little-endian wire readers (endian-safe, no struct casting) */
static inline uint32_t lc_rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* finite IEEE-754 binary32 check (NaN/Inf must be rejected, §5.2) */
static inline int lc_finite_f32_bits(uint32_t bits)
{
    return ((bits & 0x7F800000u) != 0x7F800000u) ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* LC_APP_ABI_V2_H */
