/*
 * lc_bus.h — Line Crossing App business layer (Issue #11).
 *
 * Consumes the frozen v2 Host ABI (via the lcbus_host_ops adapter, bound to
 * the real 48B function table by lc_app_entry.c) and implements the counting-
 * parity statistics business on top of the already-accepted lc_* core:
 *   - single configured target class, generation-bound resolution (§5.2/§6.5)
 *   - center-point/tracker/line-crossing feeding of the lc core
 *   - window IN/OUT, cumulative totals, target-switch/manual-reset semantics
 *   - counter-name edits never reset counters (counting principle)
 *   - visible GAP/lost-frame/backpressure accounting (never silently exact)
 *   - model-incompatible / recovery states
 *   - state_read/state_commit persistence with expected_revision semantics
 *   - schema_version=1 / type=line_counting report construction and
 *     report_submit/report_status delivery with accepted-vs-delivered split
 *
 * The struct is exposed so host contract tests can assert on internals;
 * nothing here links NE301 platform code.
 */
#ifndef LC_BUS_H
#define LC_BUS_H

#include <stdint.h>
#include "lc_app_abi_v2.h"
#include "lc_bus_config.h"
#include "lc_tracker.h"

/* ---- compiled-in identity (packaging --app-id must match LC_APP_ID) ---- */
#ifndef LC_APP_ID
#define LC_APP_ID "line-crossing"
#endif
#ifndef LC_APP_SW_VERSION
#define LC_APP_SW_VERSION "1.0.0"
#endif
#define LC_APP_DEVICE_ID "ne301-app:" LC_APP_ID

/* report content caps (deterministic content policy, documented in
 * docs/p7-app.md; on overflow the WHOLE report is dropped, never truncated) */
#define LCBUS_REPORT_MAX_TRACKS 12u
#define LCBUS_REPORT_MAX_POINTS 8u
#define LCBUS_HEAT_DIM          16u
#define LCBUS_HEAT_SIZE         (LCBUS_HEAT_DIM * LCBUS_HEAT_DIM)

/* persistence flush pacing (tick-domain ms) */
#define LCBUS_FLUSH_INTERVAL_MS  5000u
#define LCBUS_REBIND_RETRY_MS    1000u

/* ---- Host ops adapter (implemented over the v2 table in lc_app_entry.c) - */

typedef struct lcbus_host_ops {
    void    *user;
    int32_t (*model_meta)(void *user, uint8_t *out128);
    int32_t (*class_name)(void *user, uint32_t model_gen, uint32_t class_gen,
                          uint32_t class_index, char *out_utf8, uint32_t cap,
                          uint32_t *actual_len);
    uint32_t (*tick_ms)(void *user);
    int32_t (*state_read)(void *user, uint8_t *out, uint32_t cap,
                          uint32_t *actual_len, uint32_t *out_revision);
    int32_t (*state_commit)(void *user, const uint8_t *blob, uint32_t len,
                            uint32_t expected_revision, uint32_t *new_revision);
    int32_t (*report_submit)(void *user, const uint8_t *json, uint32_t len,
                             uint32_t app_report_seq, uint32_t *out_host_boot_id);
    int32_t (*report_status)(void *user, uint32_t host_boot_id, uint32_t report_seq,
                             uint32_t *out_mqtt_state, uint32_t *out_webhook_state);
    void    (*log)(void *user, const char *text);
} lcbus_host_ops_t;

/* the one adapter over a real lc_app_api_v2_t table (user = table pointer) */
const lcbus_host_ops_t *lcbus_abi_ops(void);

/* ---- model binding / states -------------------------------------------- */

typedef enum {
    LCBUS_MSTATE_RUNNING = 0,
    LCBUS_MSTATE_UNSUPPORTED_MODEL,    /* not loaded / wrong type / bad meta */
    LCBUS_MSTATE_TARGET_CLASS_INVALID  /* label missing/unmatchable/expired  */
} lcbus_model_state_t;

typedef enum {
    LCBUS_PERSIST_OK = 0,
    LCBUS_PERSIST_NONE,      /* verified absence (NOT_FOUND / revision 0) */
    LCBUS_PERSIST_DEGRADED,  /* storage indeterminate/failing; not exact   */
    LCBUS_PERSIST_CORRUPT,   /* stored blob failed integrity/content check */
    LCBUS_PERSIST_CONFLICT   /* unresolved commit conflict; auto-flush off */
} lcbus_persist_state_t;

typedef struct lcbus_binding {
    uint8_t  bound;
    uint32_t model_generation;
    uint32_t class_generation;
    uint32_t class_count;
    int32_t  target_index;
    char     target_name[LC_TARGET_CLASS_NAME_LEN];
    char     model_name[LC_MODEL_NAME_LEN];
    char     model_version[LC_MODEL_VERSION_LEN];
} lcbus_binding_t;

typedef struct lcbus_stats {
    /* stream observability (AC2: gaps/backpressure visible, not silently exact) */
    uint32_t frames_total;
    uint32_t frames_empty;      /* FRAME kind with detection_count == 0       */
    uint32_t frames_unusable;   /* deliverable frames the app could not use   */
    uint32_t no_event_polls;    /* event_next == NO_EVENT                     */
    uint32_t host_faults;       /* v2 contract violations observed            */
    uint32_t malformed_events;  /* wire-level rejects (kind/flags/len/floats) */
    uint32_t gaps_total;        /* GAP events + gap-flagged frames            */
    uint32_t lost_frames_total; /* known lost frames (mod window counters)    */
    uint32_t lost_unknown_events;
    uint32_t model_rebinds;
    uint32_t alloc_failures;
    /* reports: platform-accept vs channel-delivery are distinct (AC4/§6.6)   */
    uint32_t reports_submitted;       /* report_submit returned OK            */
    uint32_t reports_dropped;         /* overflow/quota/io — dropped visibly  */
    uint32_t reports_failed_transport;
    uint32_t reports_delivered_mqtt;
    uint32_t reports_delivered_webhook;
    uint32_t reports_status_unresolved;
    /* persistence                                                            */
    uint32_t state_commits_ok;
    uint32_t state_commit_failures;
    uint32_t state_conflicts;
} lcbus_stats_t;

#define LCBUS_PENDING_MAX 8

typedef struct lcbus_pending {
    uint32_t seq;
    uint32_t polls;
    uint8_t  in_use;
    uint8_t  mqtt_done;
    uint8_t  web_done;
} lcbus_pending_t;

typedef struct lcbus {
    lcbus_host_ops_t      ops;
    lc_bus_config_t       cfg;
    lcbus_binding_t       binding;
    lcbus_model_state_t   model_state;
    lcbus_persist_state_t persist_state;

    lc_tracker_t   *tracker;
    lc_line_cross_t *line;
    uint32_t        next_id_carry;
    uint32_t        consecutive_alloc_failures;

    uint32_t window_in, window_out, total_in, total_out;
    uint32_t window_start_ms;      /* tick domain */
    uint8_t  window_carried;       /* window counters restored from a previous
                                    * session; reported until first close    */
    uint32_t carried_in, carried_out;

    uint32_t gaps_window, lost_window;
    uint8_t  lost_unknown_window;
    uint32_t unusable_window;

    uint32_t report_seq;
    uint32_t host_boot_id;
    uint8_t  host_boot_known;

    lcbus_pending_t pending[LCBUS_PENDING_MAX];

    uint8_t  state_dirty;
    uint32_t revision;             /* last known host state revision */
    uint32_t last_flush_ms;
    uint8_t  last_flush_valid;
    uint32_t last_rebind_ms;
    uint8_t  last_rebind_valid;

    uint32_t heat[LCBUS_HEAT_SIZE];

    lcbus_stats_t st;
    uint8_t  session_fatal;        /* UNAUTHORIZED seen; entry must exit   */
    uint8_t  resource_fatal;       /* persistent allocation exhaustion     */
    uint8_t  stop_requested;       /* STOPPING event seen                  */
} lcbus_t;

/* ---- lifecycle ---------------------------------------------------------- */

void lcbus_init(lcbus_t *b, const lcbus_host_ops_t *ops);
/* state_read + decode; distinguishes verified-absence from degraded/corrupt */
void lcbus_restore(lcbus_t *b);
/* model_meta + generation-bound class scan; sets model_state/binding.
 * force=1 bypasses the retry pacing (frame generation change/MODEL_CHANGED);
 * force=0 is the rate-limited retry used from the idle path. */
void lcbus_rebind(lcbus_t *b, int force);

/* ---- event stream ------------------------------------------------------- */

/* dispatch one event_next frame (raw wire bytes; strictly validated) */
void lcbus_on_event(lcbus_t *b, const uint8_t *ev, uint32_t len);
/* NO_EVENT housekeeping: window tick, status poll, rebind retry, flush due */
void lcbus_on_idle(lcbus_t *b);

/* ---- persistence -------------------------------------------------------- */

/* flush dirty state via state_commit(expected_revision); force ignores pacing */
void lcbus_flush(lcbus_t *b, int force);

/* ---- business actions (counting parity; driven by management tooling) --- */

/* returns 0 on success; on target change resets totals+window+transient and
 * rebinds; counter_name-only edits NEVER touch counters */
int  lcbus_apply_config(lcbus_t *b, const lc_bus_config_t *candidate);
/* manual reset: zero totals/window/quality, clear transient, persist */
void lcbus_reset(lcbus_t *b);

#endif
