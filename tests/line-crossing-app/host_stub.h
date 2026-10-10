/*
 * host_stub.h — fixture-driven Host ABI v2 stub for offline contract tests.
 *
 * Implements ALL TEN v2 functions (§6.2 table) over a fixture the tests
 * control: event queue, model metadata + class table, state store with
 * revision semantics, report queue with per-channel delivery states, stop
 * flag, tick source, per-function fault injection and call accounting.
 *
 * BOUNDARY (Issue #11 / v2 spec §12): this stub proves the App's CALL and
 * ERROR contracts only.  It is NOT a device Host: no AI inference, no
 * session manager, no NVS/flash persistence, no MQTT/Webhook transport,
 * no signature verification.
 */
#ifndef LCSTUB_H
#define LCSTUB_H

#include <stdint.h>
#include "lc_app_abi_v2.h"

#define LCSTUB_MAX_CLASSES  16
#define LCSTUB_MAX_EVENTS   64
#define LCSTUB_MAX_REPORTS  16
#define LCSTUB_LOG_LINES    64
#define LCSTUB_LOG_LINE_LEN 96
#define LCSTUB_STATE_CAP    4096
#define LCSTUB_EVENT_MAX    1600

/* function ids for fault injection / call accounting */
typedef enum {
    LCSTUB_FN_LOG = 0,
    LCSTUB_FN_TICK,
    LCSTUB_FN_EVENT_NEXT,
    LCSTUB_FN_MODEL_META,
    LCSTUB_FN_CLASS_NAME,
    LCSTUB_FN_REPORT_SUBMIT,
    LCSTUB_FN_REPORT_STATUS,
    LCSTUB_FN_STATE_READ,
    LCSTUB_FN_STATE_COMMIT,
    LCSTUB_FN_SHOULD_STOP,
    LCSTUB_FN_COUNT
} lcstub_fn_t;

typedef struct {
    float    x, y, w, h, conf;
    uint32_t class_index;
} lcstub_det_t;

typedef struct {
    int      present;
    uint32_t seq;
    uint32_t len;
    uint8_t  bytes[LCSTUB_EVENT_MAX];
    uint32_t mqtt_state;
    uint32_t web_state;
} lcstub_report_t;

typedef struct lcstub {
    /* session */
    int      authorized;
    int      stop_flag;
    uint32_t tick_now;
    uint32_t tick_step;      /* added on every tick_ms() call (0 = frozen) */

    /* model fixture */
    int      model_loaded;
    uint32_t model_gen, class_gen, class_count;
    const char *meta_result_type_override; /* NULL = 1 (PP_TYPE_OD) */
    char     model_name[64];
    char     model_version[32];
    char     classes[LCSTUB_MAX_CLASSES][32];

    /* raw meta override: when meta_raw_len != 0, model_meta returns these
     * bytes verbatim (malformed-meta negative tests) */
    uint8_t  meta_raw[LC_MODEL_META_SIZE];
    uint32_t meta_raw_len;
    uint32_t meta_cap_override; /* 0 = normal (128); nonzero = report this cap need */

    /* event queue */
    uint8_t  events[LCSTUB_MAX_EVENTS][LCSTUB_EVENT_MAX];
    uint32_t event_len[LCSTUB_MAX_EVENTS];
    int      ev_head, ev_count;
    uint32_t auto_stop_after_no_events; /* 0 = never; else stop after N NO_EVENTs */
    uint32_t no_event_streak;

    /* state store (revision-semantics memory stand-in) */
    uint8_t  state_blob[LCSTUB_STATE_CAP];
    uint32_t state_len;
    int      state_present;
    uint32_t state_revision;
    int32_t  state_read_fault;     /* 0 = off; else return this code N times */
    int      state_read_fault_times;
    int32_t  state_commit_fault;
    int      state_commit_fault_times;

    /* report queue */
    lcstub_report_t reports[LCSTUB_MAX_REPORTS];
    int      report_count;
    uint32_t boot_id;
    uint32_t default_mqtt_state;
    uint32_t default_webhook_state;
    int      verify_report_seq;    /* 1: JSON report_seq must match the arg */

    /* fault injection (generic per function; consumed N times) */
    int32_t  fault_code[LCSTUB_FN_COUNT];
    int      fault_times[LCSTUB_FN_COUNT];

    /* observation */
    uint32_t calls[LCSTUB_FN_COUNT];
    char     logs[LCSTUB_LOG_LINES][LCSTUB_LOG_LINE_LEN];
    int      log_head, log_count;
} lcstub_t;

lcstub_t *lcstub_new(void);
void      lcstub_destroy(lcstub_t *s);

/* fixture setup */
void lcstub_set_session(lcstub_t *s, int authorized);
void lcstub_set_stop(lcstub_t *s, int stop);
void lcstub_set_tick(lcstub_t *s, uint32_t t);
void lcstub_set_tick_step(lcstub_t *s, uint32_t step);
void lcstub_set_model(lcstub_t *s, int loaded, uint32_t model_gen, uint32_t class_gen,
                      uint32_t class_count, const char *model_name, const char *model_version);
void lcstub_set_class(lcstub_t *s, uint32_t index, const char *name);
void lcstub_set_meta_raw(lcstub_t *s, const uint8_t *bytes, uint32_t len);
void lcstub_set_state(lcstub_t *s, const void *blob, uint32_t len, uint32_t revision);
void lcstub_set_boot_id(lcstub_t *s, uint32_t boot_id);
void lcstub_set_report_channels(lcstub_t *s, uint32_t mqtt_state, uint32_t webhook_state);
void lcstub_set_report_state(lcstub_t *s, uint32_t seq, uint32_t mqtt_state, uint32_t web_state);
void lcstub_fault(lcstub_t *s, lcstub_fn_t fn, int32_t code, int times);
void lcstub_state_read_fault(lcstub_t *s, int32_t code, int times);
void lcstub_state_commit_fault(lcstub_t *s, int32_t code, int times);

/* event queue builders (LE wire encoders) */
void lcstub_push_raw(lcstub_t *s, const void *bytes, uint32_t len);
void lcstub_push_kind(lcstub_t *s, uint32_t kind, uint32_t seq, uint32_t mono_ms,
                      uint32_t model_gen, uint32_t class_gen,
                      uint32_t flags, uint32_t lost);
void lcstub_push_frame(lcstub_t *s, uint32_t seq, uint32_t mono_ms,
                       uint32_t model_gen, uint32_t class_gen,
                       uint32_t flags, uint32_t lost,
                       const lcstub_det_t *dets, uint32_t n);

/* wire helpers shared with tests */
void lcstub_wr32(uint8_t *p, uint32_t v);

/* the 48B v2 table bound to this stub instance */
void lcstub_make_table(lcstub_t *s, lc_app_api_v2_t *out);

/* observation helpers */
uint32_t    lcstub_calls(const lcstub_t *s, lcstub_fn_t fn);
const char *lcstub_last_log(const lcstub_t *s);
/* find the Nth (0-based) submitted report by report_seq; NULL if absent */
const lcstub_report_t *lcstub_report_by_seq(const lcstub_t *s, uint32_t seq);

#endif
