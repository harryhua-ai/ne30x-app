/*
 * lc_bus.c — Line Crossing App business layer implementation.
 *
 * Consumes the frozen v2 Host ABI through lcbus_host_ops (bound to the real
 * function table by lc_app_entry.c) and drives the already-accepted lc_*
 * core.  Counting-parity principles are kept where the frozen counting
 * semantics define them (target switch resets counters, counter-name edits
 * do not, model generation changes clear transient tracker state but keep
 * counters, manual reset zeroes everything); everything the v2 spec defines
 * (wire validation, generations, state revision, report delivery states) is
 * implemented exactly as specified — see docs/p7-app.md for the mapping.
 */
#include "lc_bus.h"
#include "lc_json.h"
#include "lc_stateblob.h"
#include "lc_line_cross.h"
#include "lc_compat.h"

/* file-scope .bss buffers (the Host loader never initializes .data) */
static char lc_report_buf[LC_APP_REPORT_MAX];

/* ---- small helpers ------------------------------------------------------ */

static float bits_to_f32(uint32_t bits)
{
    union { uint32_t u; float f; } c;
    c.u = bits;
    return c.f;
}

static uint32_t now_tick(lcbus_t *b) { return b->ops.tick_ms(b->ops.user); }

static void lc_log(lcbus_t *b, const char *s)
{
    if (b->ops.log) b->ops.log(b->ops.user, s);
}

/* ---- strict 128B model metadata decode (§6.5, fail-closed) -------------- */

static int meta_cstr_ok(const uint8_t *field, uint32_t flen)
{
    uint32_t nul = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < flen; i++) {
        if (field[i] == 0u) { nul = i; break; }
    }
    if (nul == 0xFFFFFFFFu) return 0;             /* no NUL terminator      */
    for (uint32_t i = nul; i < flen; i++) {
        if (field[i] != 0u) return 0;             /* garbage after NUL      */
    }
    /* field is NUL-terminated within its length by construction */
    return lc_bus_utf8_valid((const char *)field);
}

static int parse_meta_strict(const uint8_t *m, lcbus_binding_t *out)
{
    uint32_t loaded = lc_rd_u32(m + 0);
    uint32_t result_type = lc_rd_u32(m + 4);
    uint32_t mgen = lc_rd_u32(m + 8);
    uint32_t cgen = lc_rd_u32(m + 12);
    uint32_t class_count = lc_rd_u32(m + 16);
    uint32_t reserved0 = lc_rd_u32(m + 20);

    if (reserved0 != 0u) return 0;
    if (class_count == 0u || class_count > 65535u) return 0;
    if (!meta_cstr_ok(m + 24, LC_MODEL_NAME_LEN)) return 0;
    if (!meta_cstr_ok(m + 88, LC_MODEL_VERSION_LEN)) return 0;
    for (uint32_t i = 120u; i < 128u; i++) {
        if (m[i] != 0u) return 0;                 /* tail reserved must be 0 */
    }
    out->model_generation = mgen;
    out->class_generation = cgen;
    out->class_count = class_count;
    lc_strlcpy(out->model_name, (const char *)m + 24, sizeof(out->model_name));
    lc_strlcpy(out->model_version, (const char *)m + 88, sizeof(out->model_version));
    return (loaded != 0u && result_type == LC_MODEL_META_RESULT_OD) ? 1 : 2;
    /* 1 = usable, 2 = strict-valid but unusable for this business */
}

/* ---- transient state (counting lc_clear_transient parity) --------------- */

static void clear_transient(lcbus_t *b)
{
    if (b->tracker) {
        b->next_id_carry = lc_tracker_next_id(b->tracker);
        lc_tracker_destroy(b->tracker);
        b->tracker = NULL;
    }
    lc_memset(b->heat, 0, sizeof(b->heat));
}

static int ensure_resources(lcbus_t *b)
{
    if (!b->line) {
        b->line = lc_line_cross_create(
            b->cfg.line_x1_permille / 1000.0f, b->cfg.line_y1_permille / 1000.0f,
            b->cfg.line_x2_permille / 1000.0f, b->cfg.line_y2_permille / 1000.0f,
            b->cfg.outside_x_permille / 1000.0f, b->cfg.outside_y_permille / 1000.0f);
        if (!b->line) return 0;
    }
    if (!b->tracker) {
        lc_tracker_config_t tc;
        tc.max_dist_permille = b->cfg.max_dist_permille;
        tc.track_history_k = b->cfg.track_history_k;
        tc.max_miss = b->cfg.max_miss;
        tc.k_confirm = b->cfg.k_confirm;
        b->tracker = lc_tracker_create(&tc, b->next_id_carry);
        if (!b->tracker) return 0;
    }
    b->consecutive_alloc_failures = 0;
    return 1;
}

/* ---- binding ------------------------------------------------------------- */

static void unbind(lcbus_t *b, lcbus_model_state_t st)
{
    b->binding.bound = 0;
    b->binding.target_index = -1;
    b->binding.target_name[0] = '\0';
    b->model_state = st;
}

void lcbus_rebind(lcbus_t *b, int force)
{
    uint32_t now = now_tick(b);
    if (!force && b->last_rebind_valid &&
        lc_tick_diff(now, b->last_rebind_ms) < LCBUS_REBIND_RETRY_MS) {
        return;
    }
    b->last_rebind_ms = now;
    b->last_rebind_valid = 1;
    b->st.model_rebinds++;

    uint8_t meta[LC_MODEL_META_SIZE];
    int32_t r = b->ops.model_meta(b->ops.user, meta);
    if (r == LC_RET_UNAUTHORIZED) {
        b->session_fatal = 1;
        return;
    }
    if (r != LC_RET_OK) {
        /* BUFFER_TOO_SMALL for a fixed-128 query is a host contract breach;
         * INCOMPATIBLE means the Host cannot represent its metadata. */
        if (r == LC_RET_INCOMPATIBLE) {
            unbind(b, LCBUS_MSTATE_UNSUPPORTED_MODEL);
        } else {
            b->st.host_faults++;
        }
        return;
    }

    lcbus_binding_t parsed;
    lc_memset(&parsed, 0, sizeof(parsed));
    parsed.target_index = -1;
    int pr = parse_meta_strict(meta, &parsed);
    if (pr == 0) {
        unbind(b, LCBUS_MSTATE_UNSUPPORTED_MODEL);   /* malformed meta wire */
        return;
    }
    if (pr == 2) {                                   /* valid but unusable  */
        unbind(b, LCBUS_MSTATE_UNSUPPORTED_MODEL);
        /* keep generations/counters/names so change detection still works */
        b->binding.model_generation = parsed.model_generation;
        b->binding.class_generation = parsed.class_generation;
        b->binding.class_count = parsed.class_count;
        lc_strlcpy(b->binding.model_name, parsed.model_name, sizeof(b->binding.model_name));
        lc_strlcpy(b->binding.model_version, parsed.model_version, sizeof(b->binding.model_version));
        return;
    }

    /* unchanged generations with a live binding: keep counting (parity with
     * counting's lc_rebind short-circuit; no transient reset) */
    if (b->binding.bound &&
        b->binding.model_generation == parsed.model_generation &&
        b->binding.class_generation == parsed.class_generation &&
        b->binding.class_count == parsed.class_count) {
        b->model_state = LCBUS_MSTATE_RUNNING;
        return;
    }

    /* generation change: clear transient tracker state, keep counters
     * (counting lc_rebind parity) */
    if (b->binding.bound) clear_transient(b);

    b->binding.model_generation = parsed.model_generation;
    b->binding.class_generation = parsed.class_generation;
    b->binding.class_count = parsed.class_count;
    lc_strlcpy(b->binding.model_name, parsed.model_name, sizeof(b->binding.model_name));
    lc_strlcpy(b->binding.model_version, parsed.model_version, sizeof(b->binding.model_version));

    /* generation-bound class scan for the configured target (§6.5) */
    char name[64];
    int32_t found = -1;
    for (uint32_t i = 0; i < parsed.class_count; i++) {
        uint32_t alen = 0;
        int32_t cr = b->ops.class_name(b->ops.user, parsed.model_generation,
                                       parsed.class_generation, i,
                                       name, (uint32_t)sizeof(name), &alen);
        if (cr == LC_RET_UNAUTHORIZED) {
            b->session_fatal = 1;
            return;
        }
        if (cr == LC_RET_BUFFER_TOO_SMALL) {
            /* longer than 63 bytes: can never equal a <=31-byte target
             * (§5.4: never truncate into a seemingly valid label) */
            continue;
        }
        if (cr == LC_RET_INCOMPATIBLE) {
            /* generation expired mid-scan; retry via the idle path */
            unbind(b, LCBUS_MSTATE_TARGET_CLASS_INVALID);
            return;
        }
        if (cr != LC_RET_OK) {
            b->st.host_faults++;
            unbind(b, LCBUS_MSTATE_TARGET_CLASS_INVALID);
            return;
        }
        if (alen >= (uint32_t)sizeof(name)) {        /* contract breach      */
            b->st.host_faults++;
            unbind(b, LCBUS_MSTATE_TARGET_CLASS_INVALID);
            return;
        }
        name[alen] = '\0';
        if (lc_strcmp(name, b->cfg.target_class_name) == 0) {
            found = (int32_t)i;
            break;
        }
    }

    if (found < 0) {
        unbind(b, LCBUS_MSTATE_TARGET_CLASS_INVALID);
        return;
    }
    b->binding.bound = 1;
    b->binding.target_index = found;
    lc_strlcpy(b->binding.target_name, b->cfg.target_class_name,
               sizeof(b->binding.target_name));
    b->model_state = LCBUS_MSTATE_RUNNING;
}

/* ---- gap / quality accounting (never silently exact, §5.3) -------------- */
/* handled inline in lcbus_on_event; see apply of flags + GAP kind there.   */

/* ---- event validation (§5, fail-closed) ---------------------------------- */

typedef struct lc_evt_hdr {
    uint32_t total_len, kind, sequence, monotonic_ms;
    uint32_t model_gen, class_gen, flags, detection_count, lost, reserved0;
} lc_evt_hdr_t;

static int validate_event(lcbus_t *b, const uint8_t *ev, uint32_t len,
                          lc_evt_hdr_t *h)
{
    if (len < LC_EVT_HDR_SIZE) return 0;
    h->total_len = lc_rd_u32(ev + 4 * LC_EVTH_TOTAL_LEN);
    h->kind = lc_rd_u32(ev + 4 * LC_EVTH_KIND);
    h->sequence = lc_rd_u32(ev + 4 * LC_EVTH_SEQUENCE);
    h->monotonic_ms = lc_rd_u32(ev + 4 * LC_EVTH_MONOTONIC_MS);
    h->model_gen = lc_rd_u32(ev + 4 * LC_EVTH_MODEL_GEN);
    h->class_gen = lc_rd_u32(ev + 4 * LC_EVTH_CLASS_GEN);
    h->flags = lc_rd_u32(ev + 4 * LC_EVTH_FLAGS);
    h->detection_count = lc_rd_u32(ev + 4 * LC_EVTH_DETECTION_COUNT);
    h->lost = lc_rd_u32(ev + 4 * LC_EVTH_LOST_FRAME_COUNT);
    h->reserved0 = lc_rd_u32(ev + 4 * LC_EVTH_RESERVED0);

    if (h->total_len != len) return 0;
    if (h->reserved0 != 0u) return 0;
    if (h->kind < LC_EVT_KIND_FRAME || h->kind > LC_EVT_KIND_STOPPING) return 0;
    if (h->flags & ~LC_EVT_FLAGS_VALID_MASK) return 0;
    if ((h->flags & LC_EVT_FLAG_LOST_UNKNOWN) &&
        h->lost != LC_EVT_LOST_UNKNOWN_MARK) return 0;
    if (h->kind != LC_EVT_KIND_FRAME && h->detection_count != 0u) return 0;
    if (h->kind == LC_EVT_KIND_FRAME) {
        if (h->detection_count > LC_EVT_MAX_DETECTIONS) return 0;
        if (len != LC_EVT_HDR_SIZE + h->detection_count * LC_EVT_REC_SIZE) return 0;
        for (uint32_t i = 0; i < h->detection_count; i++) {
            const uint8_t *rec = ev + LC_EVT_HDR_SIZE + i * LC_EVT_REC_SIZE;
            for (uint32_t f = 0; f < 5u; f++) {
                if (!lc_finite_f32_bits(lc_rd_u32(rec + 4 * f))) return 0;
            }
            uint32_t cls = lc_rd_u32(rec + 4 * LC_EVT_REC_CLASS_INDEX);
            if (b->binding.class_count != 0u && cls >= b->binding.class_count) {
                return 0;                             /* §5.2 class_index bound */
            }
        }
    }
    return 1;
}

/* ---- frame processing ----------------------------------------------------- */

static void heat_cb(const lc_track_t *trk, void *user)
{
    uint32_t *heat = (uint32_t *)user;
    lc_point_t p = trk->last_pos;
    int gx = (int)(p.x * (float)LCBUS_HEAT_DIM);
    int gy = (int)(p.y * (float)LCBUS_HEAT_DIM);
    if (gx < 0) gx = 0;
    if (gy < 0) gy = 0;
    if (gx > (int)LCBUS_HEAT_DIM - 1) gx = (int)LCBUS_HEAT_DIM - 1;
    if (gy > (int)LCBUS_HEAT_DIM - 1) gy = (int)LCBUS_HEAT_DIM - 1;
    heat[gy * LCBUS_HEAT_DIM + gx]++;
}

static void process_frame(lcbus_t *b, const uint8_t *ev, const lc_evt_hdr_t *h)
{
    b->st.frames_total++;
    if (h->detection_count == 0u) b->st.frames_empty++;

    /* binding currency: generation changes force a rebind (§5.1 field 4/5) */
    if (b->binding.bound &&
        (h->model_gen != b->binding.model_generation ||
         h->class_gen != b->binding.class_generation)) {
        lcbus_rebind(b, 1);
    } else if (!b->binding.bound) {
        lcbus_rebind(b, 0);
    }
    if (!b->binding.bound || b->model_state != LCBUS_MSTATE_RUNNING) {
        /* deliverable frame the business cannot consume: visible, never
         * silently treated as counted-or-empty (§5.2) */
        b->st.frames_unusable++;
        b->unusable_window++;
        return;
    }

    lc_point_t centers[LC_EVT_MAX_DETECTIONS];
    uint8_t n = 0;
    float thr = (float)b->cfg.conf_threshold_permille / 1000.0f;
    for (uint32_t i = 0; i < h->detection_count; i++) {
        const uint8_t *rec = ev + LC_EVT_HDR_SIZE + i * LC_EVT_REC_SIZE;
        if (lc_rd_u32(rec + 4 * LC_EVT_REC_CLASS_INDEX) != (uint32_t)b->binding.target_index) {
            continue;                                  /* single target class */
        }
        float conf = bits_to_f32(lc_rd_u32(rec + 4 * LC_EVT_REC_CONF_BITS));
        if (conf < thr) continue;
        float x = bits_to_f32(lc_rd_u32(rec + 4 * LC_EVT_REC_X_BITS));
        float y = bits_to_f32(lc_rd_u32(rec + 4 * LC_EVT_REC_Y_BITS));
        float w = bits_to_f32(lc_rd_u32(rec + 4 * LC_EVT_REC_WIDTH_BITS));
        float hh = bits_to_f32(lc_rd_u32(rec + 4 * LC_EVT_REC_HEIGHT_BITS));
        centers[n].x = x + w * 0.5f;
        centers[n].y = y + hh * 0.5f;
        n++;
    }

    if (!ensure_resources(b)) {
        b->st.alloc_failures++;
        b->consecutive_alloc_failures++;
        b->st.frames_unusable++;
        b->unusable_window++;
        if (b->consecutive_alloc_failures >= 16u) {
            /* persistent resource exhaustion is fatal for the session */
            b->resource_fatal = 1;
        }
        return;
    }

    lc_track_record_t **recs = NULL;
    uint16_t n_recs = 0;
    lc_tracker_update(b->tracker, n > 0 ? centers : NULL, n, h->monotonic_ms,
                      &recs, &n_recs);
    for (uint16_t k = 0; k < n_recs; k++) LC_FREE(recs[k]);
    if (recs) LC_FREE(recs);

    lc_cross_evt_t evts[16];
    uint8_t n_evts = 0;
    uint32_t win_in = 0, win_out = 0;
    lc_tracker_check_line_crossings(b->tracker, b->line, h->monotonic_ms,
                                    &win_in, &win_out,
                                    &b->total_in, &b->total_out,
                                    evts, (uint8_t)(sizeof(evts) / sizeof(evts[0])),
                                    &n_evts);
    b->window_in += win_in;
    b->window_out += win_out;
    if (win_in + win_out > 0u) b->state_dirty = 1;

    if (b->cfg.heat_grid_enable) {
        lc_tracker_for_each_stable(b->tracker, heat_cb, b->heat);
    }
}

/* ---- report construction (schema_version=1, type=line_counting) ---------- */

static void lcj_key(lc_json_t *j, const char *key)
{
    lcj_raw(j, "\"");
    lcj_raw(j, key);
    lcj_raw(j, "\":");
}

static void build_tracks(lc_json_t *j, lc_track_record_t **records, uint16_t n_records)
{
    lcj_key(j, "tracks");
    lcj_raw(j, "[");
    uint16_t n = n_records < LCBUS_REPORT_MAX_TRACKS ? n_records
                                                     : (uint16_t)LCBUS_REPORT_MAX_TRACKS;
    for (uint16_t i = 0; i < n && records; i++) {
        const lc_track_record_t *r = records[i];
        if (i) lcj_raw(j, ",");
        lcj_raw(j, "{");
        lcj_key(j, "track_id"); lcj_u32(j, r->track_id);
        lcj_raw(j, ",");
        lcj_key(j, "segment_id"); lcj_u32(j, r->segment_id);
        lcj_raw(j, ",");
        lcj_key(j, "entered_at_ms"); lcj_u32(j, r->entered_at_ms);
        lcj_raw(j, ",");
        lcj_key(j, "seg_start_ms"); lcj_u32(j, r->seg_start_ms);
        lcj_raw(j, ",");
        lcj_key(j, "seg_end_ms"); lcj_u32(j, r->seg_end_ms);
        lcj_raw(j, ",");
        lcj_key(j, "seg_end_type");
        lcj_string(j, (r->seg_end_type == LC_SEG_CROSSING) ? "crossing" : "departed");
        lcj_raw(j, ",");
        lcj_key(j, "events"); lcj_raw(j, "[");
        int first = 1;
        if (r->events & LC_BIT_IN) { lcj_string(j, "line_cross_in"); first = 0; }
        if (r->events & LC_BIT_OUT) { if (!first) lcj_raw(j, ","); lcj_string(j, "line_cross_out"); }
        lcj_raw(j, "],");
        lcj_key(j, "points"); lcj_raw(j, "[");
        const uint32_t *pts_ts = lc_track_record_point_ts_const(r);
        uint8_t np = r->nb_points < LCBUS_REPORT_MAX_POINTS
                         ? r->nb_points : (uint8_t)LCBUS_REPORT_MAX_POINTS;
        for (uint8_t p = 0; p < np; p++) {
            if (p) lcj_raw(j, ",");
            lcj_raw(j, "[");
            lcj_coord(j, r->points[p].x);
            lcj_raw(j, ",");
            lcj_coord(j, r->points[p].y);
            lcj_raw(j, ",");
            lcj_u32(j, pts_ts[p]);
            lcj_raw(j, "]");
        }
        lcj_raw(j, "]}");
    }
    lcj_raw(j, "]");
}

static uint32_t build_window_report(lcbus_t *b, uint32_t end_ms,
                                    lc_track_record_t **records, uint16_t n_records)
{
    lc_json_t j;
    lcj_init(&j, lc_report_buf, (uint32_t)sizeof(lc_report_buf));

    lcj_raw(&j, "{");
    lcj_key(&j, "schema_version"); lcj_u32(&j, 1);
    lcj_raw(&j, ",");
    lcj_key(&j, "type"); lcj_string(&j, "line_counting");
    lcj_raw(&j, ",");
    lcj_key(&j, "device_id"); lcj_string(&j, LC_APP_DEVICE_ID);
    lcj_raw(&j, ",");
    lcj_key(&j, "app");
    lcj_raw(&j, "{");
    lcj_key(&j, "app_id"); lcj_string(&j, LC_APP_ID);
    lcj_raw(&j, ",");
    lcj_key(&j, "sw_version"); lcj_string(&j, LC_APP_SW_VERSION);
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");
    lcj_key(&j, "boot_id"); lcj_u32(&j, b->host_boot_id);
    lcj_raw(&j, ",");
    lcj_key(&j, "report_seq"); lcj_u32(&j, b->report_seq + 1u);
    lcj_raw(&j, ",");
    /* no RTC in the App session: honest absence, counting shape preserved */
    lcj_key(&j, "clock_valid"); lcj_bool(&j, 0);
    lcj_raw(&j, ",");
    lcj_key(&j, "reported_at"); lcj_null(&j);
    lcj_raw(&j, ",");

    uint32_t dur_sec = lc_tick_diff(end_ms, b->window_start_ms) / 1000u;
    lcj_key(&j, "window");
    lcj_raw(&j, "{");
    lcj_key(&j, "start_time"); lcj_null(&j);
    lcj_raw(&j, ",");
    lcj_key(&j, "end_time"); lcj_null(&j);
    lcj_raw(&j, ",");
    lcj_key(&j, "start_ms"); lcj_u32(&j, b->window_start_ms);
    lcj_raw(&j, ",");
    lcj_key(&j, "end_ms"); lcj_u32(&j, end_ms);
    lcj_raw(&j, ",");
    lcj_key(&j, "duration_sec"); lcj_u32(&j, dur_sec);
    lcj_raw(&j, ",");
    lcj_key(&j, "in"); lcj_u32(&j, b->window_in);
    lcj_raw(&j, ",");
    lcj_key(&j, "out"); lcj_u32(&j, b->window_out);
    lcj_raw(&j, ",");
    lcj_key(&j, "carried_in"); lcj_u32(&j, b->carried_in);
    lcj_raw(&j, ",");
    lcj_key(&j, "carried_out"); lcj_u32(&j, b->carried_out);
    lcj_raw(&j, ",");
    lcj_key(&j, "data_quality");
    lcj_raw(&j, "{");
    lcj_key(&j, "complete");
    lcj_bool(&j, (b->gaps_window == 0u && b->lost_window == 0u &&
                  !b->lost_unknown_window && b->unusable_window == 0u));
    lcj_raw(&j, ",");
    lcj_key(&j, "gaps"); lcj_u32(&j, b->gaps_window);
    lcj_raw(&j, ",");
    lcj_key(&j, "lost_frames"); lcj_u32(&j, b->lost_window);
    lcj_raw(&j, ",");
    lcj_key(&j, "lost_unknown"); lcj_bool(&j, b->lost_unknown_window);
    lcj_raw(&j, ",");
    lcj_key(&j, "frames_unusable"); lcj_u32(&j, b->unusable_window);
    lcj_raw(&j, ",");
    lcj_key(&j, "persist_ok");
    lcj_bool(&j, b->persist_state == LCBUS_PERSIST_OK ||
                  b->persist_state == LCBUS_PERSIST_NONE);
    lcj_raw(&j, "}");
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");

    lcj_key(&j, "total");
    lcj_raw(&j, "{");
    lcj_key(&j, "in"); lcj_u32(&j, b->total_in);
    lcj_raw(&j, ",");
    lcj_key(&j, "out"); lcj_u32(&j, b->total_out);
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");

    lcj_key(&j, "counter");
    lcj_raw(&j, "{");
    lcj_key(&j, "counter_name"); lcj_string(&j, b->cfg.counter_name);
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");

    lcj_key(&j, "target");
    lcj_raw(&j, "{");
    lcj_key(&j, "class_name"); lcj_string(&j, b->cfg.target_class_name);
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");

    lcj_key(&j, "model");
    lcj_raw(&j, "{");
    lcj_key(&j, "name"); lcj_string(&j, b->binding.model_name);
    lcj_raw(&j, ",");
    lcj_key(&j, "version"); lcj_string(&j, b->binding.model_version);
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");

    lcj_key(&j, "line");
    lcj_raw(&j, "{");
    lcj_key(&j, "x1"); lcj_permille(&j, b->cfg.line_x1_permille);
    lcj_raw(&j, ",");
    lcj_key(&j, "y1"); lcj_permille(&j, b->cfg.line_y1_permille);
    lcj_raw(&j, ",");
    lcj_key(&j, "x2"); lcj_permille(&j, b->cfg.line_x2_permille);
    lcj_raw(&j, ",");
    lcj_key(&j, "y2"); lcj_permille(&j, b->cfg.line_y2_permille);
    lcj_raw(&j, ",");
    lcj_key(&j, "outside_x"); lcj_permille(&j, b->cfg.outside_x_permille);
    lcj_raw(&j, ",");
    lcj_key(&j, "outside_y"); lcj_permille(&j, b->cfg.outside_y_permille);
    lcj_raw(&j, "}");
    lcj_raw(&j, ",");

    lcj_key(&j, "config");
    lcj_raw(&j, "{");
    lcj_key(&j, "confidence_threshold"); lcj_permille(&j, b->cfg.conf_threshold_permille);
    lcj_raw(&j, "}");

    if (b->cfg.tracks_report_enable) {
        lcj_raw(&j, ",");
        build_tracks(&j, records, n_records);
    }
    if (b->cfg.heat_grid_enable) {
        lcj_raw(&j, ",");
        lcj_key(&j, "heat_grid");
        lcj_raw(&j, "{");
        lcj_key(&j, "width"); lcj_u32(&j, LCBUS_HEAT_DIM);
        lcj_raw(&j, ",");
        lcj_key(&j, "height"); lcj_u32(&j, LCBUS_HEAT_DIM);
        lcj_raw(&j, ",");
        lcj_key(&j, "data"); lcj_raw(&j, "[");
        for (uint32_t i = 0; i < LCBUS_HEAT_SIZE; i++) {
            if (i) lcj_raw(&j, ",");
            lcj_u32(&j, b->heat[i]);
        }
        lcj_raw(&j, "]");
        lcj_raw(&j, "}");
    }
    lcj_raw(&j, "}");

    if (j.overflow) return 0;   /* never submit a truncated report (§4.1) */
    return j.len;
}

/* ---- report submit + status ---------------------------------------------- */

static void pending_push(lcbus_t *b, uint32_t seq)
{
    for (uint32_t i = 0; i < LCBUS_PENDING_MAX; i++) {
        if (!b->pending[i].in_use) {
            b->pending[i].in_use = 1;
            b->pending[i].seq = seq;
            b->pending[i].polls = 0;
            b->pending[i].mqtt_done = 0;
            b->pending[i].web_done = 0;
            return;
        }
    }
    /* ring full: oldest slot is evicted; its delivery state stays unknown */
    b->st.reports_status_unresolved++;
    b->pending[0].in_use = 1;
    b->pending[0].seq = seq;
    b->pending[0].polls = 0;
    b->pending[0].mqtt_done = 0;
    b->pending[0].web_done = 0;
}

static void submit_window_report(lcbus_t *b, uint32_t end_ms,
                                 lc_track_record_t **records, uint16_t n_records)
{
    uint32_t len = build_window_report(b, end_ms, records, n_records);
    if (len == 0u) {
        /* overflow (or builder fault): dropped visibly, never truncated */
        b->st.reports_dropped++;
        lc_log(b, "LC_APP: window report overflow -> dropped (no truncation)");
        b->state_dirty = 1;
        return;
    }
    uint32_t seq = b->report_seq + 1u;
    uint32_t boot = 0;
    int32_t r = b->ops.report_submit(b->ops.user, (const uint8_t *)lc_report_buf,
                                     len, seq, &boot);
    b->report_seq = seq;                 /* identity advanced regardless     */
    b->state_dirty = 1;
    switch (r) {
    case LC_RET_OK:
        b->st.reports_submitted++;       /* platform acceptance ONLY (§6.6)  */
        if (!b->host_boot_known) {
            b->host_boot_id = boot;
            b->host_boot_known = 1;
        }
        pending_push(b, seq);
        break;
    case LC_RET_QUOTA_EXCEEDED:
    case LC_RET_IO_ERROR:
    case LC_RET_STORAGE_UNKNOWN:
    case LC_RET_BUSY:
        b->st.reports_dropped++;
        break;
    case LC_RET_UNAUTHORIZED:
        b->session_fatal = 1;
        break;
    case LC_RET_STOPPING:
        b->stop_requested = 1;
        b->st.reports_dropped++;
        break;
    default:
        b->st.host_faults++;
        b->st.reports_dropped++;
        break;
    }
}

static void poll_statuses(lcbus_t *b)
{
    if (!b->host_boot_known) return;
    for (uint32_t i = 0; i < LCBUS_PENDING_MAX; i++) {
        lcbus_pending_t *p = &b->pending[i];
        if (!p->in_use) continue;
        uint32_t m = 0, w = 0;
        int32_t r = b->ops.report_status(b->ops.user, b->host_boot_id, p->seq, &m, &w);
        if (r == LC_RET_OK) {
            if (!p->mqtt_done) {
                if (m == LC_RSTATE_TRANSPORT_SUCCEEDED) {
                    p->mqtt_done = 1;
                    b->st.reports_delivered_mqtt++;
                } else if (m == LC_RSTATE_TRANSPORT_FAILED) {
                    p->mqtt_done = 1;
                    b->st.reports_failed_transport++;
                } else if (m == LC_RSTATE_NOT_CONFIGURED) {
                    p->mqtt_done = 1;
                }
            }
            if (!p->web_done) {
                if (w == LC_RSTATE_TRANSPORT_SUCCEEDED) {
                    p->web_done = 1;
                    b->st.reports_delivered_webhook++;
                } else if (w == LC_RSTATE_TRANSPORT_FAILED) {
                    p->web_done = 1;
                    b->st.reports_failed_transport++;
                } else if (w == LC_RSTATE_NOT_CONFIGURED) {
                    p->web_done = 1;
                }
            }
            p->polls++;
        } else if (r == LC_RET_NOT_FOUND) {
            p->polls++;
        } else if (r == LC_RET_UNAUTHORIZED) {
            b->session_fatal = 1;
            return;
        } else {
            p->polls++;                  /* transient host faults: keep trying */
        }
        if (p->mqtt_done && p->web_done) {
            p->in_use = 0;
        } else if (p->polls >= 240u) {
            p->in_use = 0;
            b->st.reports_status_unresolved++;
        }
    }
}

/* ---- window lifecycle ------------------------------------------------------ */

static void close_window(lcbus_t *b, uint32_t now)
{
    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;
    if (b->cfg.tracks_report_enable && b->tracker) {
        lc_tracker_window_snapshot(b->tracker, now, &records, &n_records);
    }
    submit_window_report(b, now, records, n_records);
    for (uint16_t k = 0; k < n_records; k++) LC_FREE(records[k]);
    if (records) LC_FREE(records);

    b->window_in = 0;
    b->window_out = 0;
    b->gaps_window = 0;
    b->lost_window = 0;
    b->lost_unknown_window = 0;
    b->unusable_window = 0;
    b->window_carried = 0;
    b->carried_in = 0;
    b->carried_out = 0;
    b->window_start_ms = now;
    b->state_dirty = 1;
}

static void maybe_close_window(lcbus_t *b, uint32_t now)
{
    uint32_t period = (uint32_t)b->cfg.window_minutes * 60000u;
    if (period == 0u) return;
    if (lc_tick_diff(now, b->window_start_ms) < period) return;
    close_window(b, now);
}

/* ---- persistence ------------------------------------------------------------ */

static void encode_state(lcbus_t *b, uint8_t *buf, uint32_t cap, uint32_t *len)
{
    *len = lc_st_encode(buf, cap, &b->cfg, b->total_in, b->total_out,
                        b->window_in, b->window_out, b->report_seq);
}

void lcbus_flush(lcbus_t *b, int force)
{
    if (b->session_fatal) return;
    if (b->persist_state == LCBUS_PERSIST_CONFLICT && !force) return;
    if (!b->state_dirty && !force) return;
    uint32_t now = now_tick(b);
    if (!force && b->last_flush_valid &&
        lc_tick_diff(now, b->last_flush_ms) < LCBUS_FLUSH_INTERVAL_MS) {
        return;
    }
    b->last_flush_ms = now;
    b->last_flush_valid = 1;

    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len = 0;
    encode_state(b, blob, (uint32_t)sizeof(blob), &len);
    if (len == 0u) {
        b->st.state_commit_failures++;
        return;
    }
    uint32_t newrev = 0;
    int32_t r = b->ops.state_commit(b->ops.user, blob, len, b->revision, &newrev);
    if (r == LC_RET_OK) {
        b->revision = newrev;
        b->state_dirty = 0;
        b->st.state_commits_ok++;
        if (b->persist_state == LCBUS_PERSIST_DEGRADED) {
            lc_log(b, "LC_APP: state storage recovered");
        } else if (b->persist_state == LCBUS_PERSIST_CORRUPT) {
            /* our valid blob now overwrote the corrupt stored bytes */
            lc_log(b, "LC_APP: corrupt state replaced with valid state");
        }
        /* a successful commit is the definition of healthy persistence */
        b->persist_state = LCBUS_PERSIST_OK;
        return;
    }
    if (r == LC_RET_UNAUTHORIZED) {
        b->session_fatal = 1;
        return;
    }
    b->st.state_commit_failures++;
    b->state_dirty = 1;
    if (r == LC_RET_REVISION_CONFLICT) {
        b->st.state_conflicts++;
        /* single-writer session: re-read the stored revision and re-commit
         * our current state; a second conflict is escalated to a visible
         * CONFLICT state with auto-flush disabled */
        uint8_t rb[LC_ST_BLOB_MAX];
        uint32_t rlen = 0, rrev = 0;
        int32_t rr = b->ops.state_read(b->ops.user, rb, (uint32_t)sizeof(rb), &rlen, &rrev);
        if (rr == LC_RET_OK) {
            b->revision = rrev;
            encode_state(b, blob, (uint32_t)sizeof(blob), &len);
            int32_t r2 = b->ops.state_commit(b->ops.user, blob, len, b->revision, &newrev);
            if (r2 == LC_RET_OK) {
                b->revision = newrev;
                b->state_dirty = 0;
                b->st.state_commits_ok++;
                b->persist_state = LCBUS_PERSIST_OK;
                return;
            }
        } else if (rr == LC_RET_NOT_FOUND) {
            b->revision = 0;
            encode_state(b, blob, (uint32_t)sizeof(blob), &len);
            int32_t r2 = b->ops.state_commit(b->ops.user, blob, len, 0u, &newrev);
            if (r2 == LC_RET_OK) {
                b->revision = newrev;
                b->state_dirty = 0;
                b->st.state_commits_ok++;
                b->persist_state = LCBUS_PERSIST_OK;
                return;
            }
        }
        lc_log(b, "LC_APP: state commit conflict unresolved -> CONFLICT state");
        b->persist_state = LCBUS_PERSIST_CONFLICT;
        return;
    }
    /* QUOTA_EXCEEDED / STORAGE_UNKNOWN / IO_ERROR / BUSY: keep dirty, retry
     * on a later flush; visibility through persist_degraded quality flag */
    if (b->persist_state != LCBUS_PERSIST_CONFLICT) {
        b->persist_state = LCBUS_PERSIST_DEGRADED;
    }
}

void lcbus_restore(lcbus_t *b)
{
    uint8_t buf[LC_ST_BLOB_MAX];
    uint32_t len = 0, rev = 0;
    int32_t r = b->ops.state_read(b->ops.user, buf, (uint32_t)sizeof(buf), &len, &rev);
    if (r == LC_RET_OK) {
        lc_bus_config_t cfg;
        uint32_t ti, to, wi, wo, seq;
        lc_st_status_t d = lc_st_decode(buf, len, &cfg, &ti, &to, &wi, &wo, &seq);
        if (d == LC_ST_OK) {
            b->cfg = cfg;
            b->total_in = ti;
            b->total_out = to;
            b->window_in = wi;
            b->window_out = wo;
            b->carried_in = wi;
            b->carried_out = wo;
            b->window_carried = (wi || wo) ? 1u : 0u;
            b->report_seq = seq;
            b->revision = rev;
            b->state_dirty = 0;
            b->persist_state = LCBUS_PERSIST_OK;
            lc_log(b, "LC_APP: persisted state restored");
            return;
        }
        /* corrupt stored blob: never silently treated as valid data */
        b->persist_state = LCBUS_PERSIST_CORRUPT;
        b->revision = rev;
        b->state_dirty = 1;
        lc_log(b, "LC_APP: stored state blob failed integrity/content check");
        return;
    }
    if (r == LC_RET_NOT_FOUND) {
        /* verified absence (§6.7): a fresh start, not a data-loss claim */
        b->persist_state = LCBUS_PERSIST_NONE;
        b->revision = 0;
        b->state_dirty = 0;
        lc_log(b, "LC_APP: no previous state (verified absence)");
        return;
    }
    if (r == LC_RET_UNAUTHORIZED) {
        b->session_fatal = 1;
        return;
    }
    /* STORAGE_UNKNOWN and friends: cannot be determined — do NOT silently
     * zero and do NOT claim completeness */
    b->persist_state = LCBUS_PERSIST_DEGRADED;
    b->revision = 0;
    b->state_dirty = 1;
    lc_log(b, "LC_APP: persisted state unreadable -> degraded persistence");
}

/* ---- event dispatch ---------------------------------------------------------- */

void lcbus_on_event(lcbus_t *b, const uint8_t *ev, uint32_t len)
{
    lc_evt_hdr_t h;
    if (!validate_event(b, ev, len, &h)) {
        b->st.malformed_events++;
        b->st.host_faults++;
        b->gaps_window++;      /* an undecodable event is a stream gap */
        b->unusable_window++;
        return;
    }

    /* gap flags can ride any event kind (§5.3); GAP kind is a dedicated gap */
    int is_gap = (h.kind == LC_EVT_KIND_GAP) ||
                 (h.flags & (LC_EVT_FLAG_LOST_KNOWN | LC_EVT_FLAG_LOST_UNKNOWN)) != 0u;
    if (is_gap) {
        b->gaps_window++;
        b->st.gaps_total++;
        if ((h.flags & LC_EVT_FLAG_LOST_UNKNOWN) || h.lost == LC_EVT_LOST_UNKNOWN_MARK) {
            b->lost_unknown_window = 1;
            b->st.lost_unknown_events++;
        } else {
            b->lost_window += h.lost;
            b->st.lost_frames_total += h.lost;
        }
    }

    switch (h.kind) {
    case LC_EVT_KIND_FRAME:
        process_frame(b, ev, &h);
        break;
    case LC_EVT_KIND_MODEL_CHANGED:
        lcbus_rebind(b, 1);
        break;
    case LC_EVT_KIND_GAP:
        break;                    /* already accounted above */
    case LC_EVT_KIND_STOPPING:
        b->stop_requested = 1;
        break;
    default:
        break;
    }

    maybe_close_window(b, now_tick(b));
}

void lcbus_on_idle(lcbus_t *b)
{
    b->st.no_event_polls++;
    poll_statuses(b);
    maybe_close_window(b, now_tick(b));
    if (b->model_state != LCBUS_MSTATE_RUNNING) {
        lcbus_rebind(b, 0);
    }
    lcbus_flush(b, 0);
}

/* ---- business actions (counting parity) --------------------------------------- */

int lcbus_apply_config(lcbus_t *b, const lc_bus_config_t *candidate)
{
    if (!candidate || !lc_bus_config_valid(candidate)) return -1;

    int target_changed = lc_strcmp(candidate->target_class_name,
                                   b->cfg.target_class_name) != 0;
    int line_changed =
        candidate->line_x1_permille != b->cfg.line_x1_permille ||
        candidate->line_y1_permille != b->cfg.line_y1_permille ||
        candidate->line_x2_permille != b->cfg.line_x2_permille ||
        candidate->line_y2_permille != b->cfg.line_y2_permille ||
        candidate->outside_x_permille != b->cfg.outside_x_permille ||
        candidate->outside_y_permille != b->cfg.outside_y_permille;
    int tracker_changed =
        candidate->max_dist_permille != b->cfg.max_dist_permille ||
        candidate->track_history_k != b->cfg.track_history_k ||
        candidate->max_miss != b->cfg.max_miss ||
        candidate->k_confirm != b->cfg.k_confirm;

    uint32_t now = now_tick(b);
    if (target_changed) {
        /* frozen counting principle: a target switch resets window AND
         * cumulative counters, transient tracker state and the binding */
        b->total_in = 0;
        b->total_out = 0;
        b->window_in = 0;
        b->window_out = 0;
        b->carried_in = 0;
        b->carried_out = 0;
        b->window_carried = 0;
        b->gaps_window = 0;
        b->lost_window = 0;
        b->lost_unknown_window = 0;
        b->unusable_window = 0;
        b->window_start_ms = now;
        clear_transient(b);
        b->binding.bound = 0;
    }
    if (line_changed && b->line) {
        lc_line_cross_destroy(b->line);
        b->line = NULL;
    }
    if (tracker_changed && b->tracker) {
        b->next_id_carry = lc_tracker_next_id(b->tracker);
        lc_tracker_destroy(b->tracker);
        b->tracker = NULL;
    }

    b->cfg = *candidate;
    if (target_changed) {
        lcbus_rebind(b, 1);
    }
    b->state_dirty = 1;
    lcbus_flush(b, 1);
    return 0;
}

void lcbus_reset(lcbus_t *b)
{
    uint32_t now = now_tick(b);
    b->total_in = 0;
    b->total_out = 0;
    b->window_in = 0;
    b->window_out = 0;
    b->carried_in = 0;
    b->carried_out = 0;
    b->window_carried = 0;
    b->gaps_window = 0;
    b->lost_window = 0;
    b->lost_unknown_window = 0;
    b->unusable_window = 0;
    b->window_start_ms = now;
    clear_transient(b);
    b->state_dirty = 1;
    lcbus_flush(b, 1);
}

/* ---- init ----------------------------------------------------------------------- */

void lcbus_init(lcbus_t *b, const lcbus_host_ops_t *ops)
{
    lc_memset(b, 0, sizeof(*b));
    b->ops = *ops;
    lc_bus_config_defaults(&b->cfg);
    b->binding.target_index = -1;
    b->model_state = LCBUS_MSTATE_UNSUPPORTED_MODEL;
    b->persist_state = LCBUS_PERSIST_NONE;
    b->next_id_carry = 1;
    b->window_start_ms = ops->tick_ms(ops->user);
}
