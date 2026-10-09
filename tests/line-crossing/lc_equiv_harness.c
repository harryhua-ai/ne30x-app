/*
 * lc_equiv_harness.c — deterministic equivalence-trace harness for the
 * ported line-crossing core (apps/line-crossing).
 *
 * Purpose (Issue #8 / P7 core): drive a fixed, scripted input sequence
 * through whichever lc_* implementation this file is compiled against
 * and print every observable output (track snapshots, ring-buffer
 * history/trail contents, archive records field-by-field, crossing
 * counters and events) as a stable text trace.
 *
 *   - compiled against pinned ne301 counting@de25a6f1 sources
 *     -> golden trace (tests/line-crossing/golden/)
 *   - compiled against the ported apps/line-crossing core
 *     -> trace that must diff clean against the golden
 *
 * Scenarios cover the actually-ported behaviors: greedy nearest
 * matching and match ordering, age confirm / miss / retirement,
 * archive-record segmentation (DEPARTED + window CROSSING chaining),
 * point subsampling intervals, in/out direction with anti-bounce
 * counted_dir state, on-line and orientation edge cases, trail
 * sampling / dedup / capacity, track-slot capacity and detect clamp,
 * serial helpers, and NULL-safety.  No platform dependencies; builds
 * with a plain C11 host compiler.
 */

#include <stdio.h>
#include <string.h>
#include "lc_tracker.h"
#include "lc_line_cross.h"

/* ---------- trace helpers ---------- */

static const char *dir_str(lc_cross_event_t d)
{
    switch (d) {
    case LC_CROSS_IN:  return "IN";
    case LC_CROSS_OUT: return "OUT";
    default:           return "NONE";
    }
}

static const char *seg_end_str(lc_seg_end_t t)
{
    return (t == LC_SEG_CROSSING) ? "CROSSING" : "DEPARTED";
}

typedef struct {
    uint32_t   id;
    lc_point_t last_pos;
    uint8_t    age;
    uint8_t    miss_count;
    int8_t     last_side;
    uint8_t    counted_dir;
    uint8_t    segment_events;
    uint32_t   segment_id;
    uint32_t   entered_at_ms;
    uint32_t   last_match_ts;
    uint32_t   last_report_ts;
    uint8_t    history_used;
    uint8_t    trail_used;
} snap_entry_t;

typedef struct {
    snap_entry_t e[LC_MAX_TRACKS];
    uint16_t     n;
} snap_t;

static void snap_visitor(const lc_track_t *trk, void *user)
{
    snap_t *s = (snap_t *)user;
    if (s->n >= LC_MAX_TRACKS) return;
    snap_entry_t *d = &s->e[s->n++];
    d->id             = trk->id;
    d->last_pos       = trk->last_pos;
    d->age            = trk->age;
    d->miss_count     = trk->miss_count;
    d->last_side      = trk->last_side;
    d->counted_dir    = trk->counted_dir;
    d->segment_events = trk->segment_events;
    d->segment_id     = trk->segment_id;
    d->entered_at_ms  = trk->entered_at_ms;
    d->last_match_ts  = trk->last_match_ts;
    d->last_report_ts = trk->last_report_ts;
    d->history_used   = trk->history_used;
    d->trail_used     = trk->trail_used;
}

static void snap_sort_by_id(snap_t *s)
{
    for (uint16_t i = 1; i < s->n; ++i) {
        snap_entry_t key = s->e[i];
        uint16_t j = i;
        while (j > 0 && s->e[j - 1].id > key.id) { s->e[j] = s->e[j - 1]; --j; }
        s->e[j] = key;
    }
}

static void dump_snap(const lc_tracker_t *t, const char *tag, uint8_t k)
{
    snap_t s;
    memset(&s, 0, sizeof(s));
    lc_tracker_for_each_stable(t, snap_visitor, &s);
    snap_sort_by_id(&s);
    printf("  snap[%s] active=%u next_id=%u n=%u\n",
           tag, (unsigned)lc_tracker_active_count(t),
           (unsigned)lc_tracker_next_id(t), (unsigned)s.n);
    for (uint16_t i = 0; i < s.n; ++i) {
        const snap_entry_t *e = &s.e[i];
        printf("    trk id=%u pos=(%.6f,%.6f) age=%u miss=%u last_side=%d "
               "counted_dir=%u seg_events=%u seg_id=%u entered=%u last_match=%u "
               "last_report=%u hist_used=%u trail_used=%u\n",
               (unsigned)e->id, e->last_pos.x, e->last_pos.y,
               (unsigned)e->age, (unsigned)e->miss_count, (int)e->last_side,
               (unsigned)e->counted_dir, (unsigned)e->segment_events,
               (unsigned)e->segment_id, (unsigned)e->entered_at_ms,
               (unsigned)e->last_match_ts, (unsigned)e->last_report_ts,
               (unsigned)e->history_used, (unsigned)e->trail_used);
    }
    (void)k;
}

static void dump_records(lc_track_record_t **records, uint16_t n)
{
    printf("  records n=%u\n", (unsigned)n);
    if (records == NULL) return;
    for (uint16_t i = 0; i < n; ++i) {
        const lc_track_record_t *r = records[i];
        if (r == NULL) { printf("    rec[%u]=NULL\n", (unsigned)i); continue; }
        printf("    rec[%u] track=%u seg=%u entered=%u start=%u end=%u end_type=%s "
               "events=%u nb_points=%u\n",
               (unsigned)i, (unsigned)r->track_id, (unsigned)r->segment_id,
               (unsigned)r->entered_at_ms, (unsigned)r->seg_start_ms,
               (unsigned)r->seg_end_ms, seg_end_str(r->seg_end_type),
               (unsigned)r->events, (unsigned)r->nb_points);
        if (r->nb_points > 0) {
            const uint32_t *ts = lc_track_record_point_ts_const(r);
            for (uint8_t p = 0; p < r->nb_points; ++p) {
                printf("      pt[%u] t=%u (%.6f,%.6f)\n",
                       (unsigned)p, (unsigned)ts[p], r->points[p].x, r->points[p].y);
            }
        }
    }
}

static void dump_counters(const char *tag, uint32_t win_in, uint32_t win_out,
                          uint32_t tot_in, uint32_t tot_out,
                          const lc_cross_evt_t *ev, uint8_t n_ev)
{
    printf("  cross[%s] win_in=%u win_out=%u tot_in=%u tot_out=%u events=%u\n",
           tag, (unsigned)win_in, (unsigned)win_out, (unsigned)tot_in,
           (unsigned)tot_out, (unsigned)n_ev);
    for (uint8_t i = 0; i < n_ev; ++i) {
        printf("    evt track=%u ts=%u dir=%s\n",
               (unsigned)ev[i].track_id, (unsigned)ev[i].ts_ms,
               dir_str(ev[i].direction));
    }
}

static void run_cross(lc_tracker_t *t, lc_line_cross_t *lc, uint32_t now_ms,
                      const char *tag)
{
    uint32_t win_in = 0, win_out = 0, tot_in = 0, tot_out = 0;
    lc_cross_evt_t ev[8];
    uint8_t n_ev = 0;
    lc_tracker_check_line_crossings(t, lc, now_ms, &win_in, &win_out,
                                    &tot_in, &tot_out, ev, 8, &n_ev);
    dump_counters(tag, win_in, win_out, tot_in, tot_out, ev, n_ev);
}

static void free_records_all(lc_track_record_t **records, uint16_t n)
{
    for (uint16_t i = 0; i < n; ++i) LC_FREE(records[i]);
    LC_FREE(records);
}

/* ring-buffer decode of history/trail for one track, by id */
typedef struct {
    uint32_t id;
    uint8_t  k;
    int      found;
    lc_point_t hist[LC_K_MAX];
    uint32_t hist_ts[LC_K_MAX];
    uint8_t  hist_n;
    lc_point_t trail[LC_HISTORY_MAX];
    uint32_t trail_ts[LC_HISTORY_MAX];
    uint8_t  trail_n;
} ring_ctx_t;

static void ring_visitor(const lc_track_t *trk, void *user)
{
    ring_ctx_t *c = (ring_ctx_t *)user;
    if (c->found || trk->id != c->id) return;
    c->found = 1;
    uint8_t k = c->k;
    c->hist_n = trk->history_used;
    for (uint8_t i = 0; i < trk->history_used; ++i) {
        uint8_t slot = (uint8_t)((trk->history_head + k - trk->history_used + i) % k);
        c->hist[i] = trk->history[slot];
        c->hist_ts[i] = trk->history_ts[slot];
    }
    c->trail_n = trk->trail_used;
    for (uint8_t i = 0; i < trk->trail_used; ++i) {
        uint8_t slot = (uint8_t)((trk->trail_head + k - trk->trail_used + i) % k);
        c->trail[i] = trk->trail[slot];
        c->trail_ts[i] = trk->trail_ts[slot];
    }
}

static void dump_track_rings(const lc_tracker_t *t, uint32_t track_id, uint8_t k,
                             const char *tag)
{
    ring_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.id = track_id;
    c.k = k;
    lc_tracker_for_each_stable(t, ring_visitor, &c);
    printf("  ring[%s] track=%u k=%u found=%d\n",
           tag, (unsigned)track_id, (unsigned)k, c.found);
    if (!c.found) return;
    printf("    hist n=%u:", (unsigned)c.hist_n);
    for (uint8_t i = 0; i < c.hist_n; ++i) {
        printf(" t%u(%.6f,%.6f)", (unsigned)c.hist_ts[i],
               c.hist[i].x, c.hist[i].y);
    }
    printf("\n");
    printf("    trail n=%u:", (unsigned)c.trail_n);
    for (uint8_t i = 0; i < c.trail_n; ++i) {
        printf(" t%u(%.6f,%.6f)", (unsigned)c.trail_ts[i],
               c.trail[i].x, c.trail[i].y);
    }
    printf("\n");
}

/* ---------- scenarios ---------- */

static void scenario_serial_helpers(void)
{
    printf("=== serial_helpers ===\n");
    printf("  next(0)=%u next(1)=%u next(0xFFFFFFFFu)=%u\n",
           (unsigned)lc_serial_next(0u), (unsigned)lc_serial_next(1u),
           (unsigned)lc_serial_next(0xFFFFFFFFu));
    printf("  newer(1,0)=%u newer(0,1)=%u newer(5,5)=%u "
           "newer(0xFFFFFFFFu,1)=%u newer(1,0xFFFFFFFFu)=%u\n",
           (unsigned)lc_serial_newer(1u, 0u), (unsigned)lc_serial_newer(0u, 1u),
           (unsigned)lc_serial_newer(5u, 5u),
           (unsigned)lc_serial_newer(0xFFFFFFFFu, 1u),
           (unsigned)lc_serial_newer(1u, 0xFFFFFFFFu));
}

static void scenario_create_edges(void)
{
    printf("=== create_edges ===\n");
    printf("  create(cfg=NULL)=%s\n",
           lc_tracker_create(NULL, 1) == NULL ? "NULL" : "non-null");
    printf("  line(degenerate)=%s\n",
           lc_line_cross_create(0.5f, 0.5f, 0.5f, 0.5f, 0.0f, 0.0f) == NULL
               ? "NULL" : "non-null");
    printf("  line(tiny-len)=%s\n",
           lc_line_cross_create(0.5f, 0.5f, 0.5f, 0.5f + 1e-4f, 0.0f, 0.0f) == NULL
               ? "NULL" : "non-null");

    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);
    /* k below minimum is clamped to 4 */
    lc_tracker_update(t, NULL, 0, 0, NULL, NULL); /* empty update on fresh tracker */
    dump_snap(t, "after-empty-update", 4);
    lc_tracker_destroy(t);
    lc_tracker_destroy(NULL);
    printf("  null-api: next_id=%u active=%u\n",
           (unsigned)lc_tracker_next_id(NULL),
           (unsigned)lc_tracker_active_count(NULL));
    lc_tracker_check_line_crossings(NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL);
    lc_tracker_for_each_stable(NULL, NULL, NULL);
    printf("  null-api: survived\n");
}

static void scenario_greedy_matching(void)
{
    printf("=== greedy_matching ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);
    lc_point_t detects[2] = { {0.10f, 0.10f}, {0.90f, 0.90f} };
    lc_tracker_update(t, detects, 2, 100, NULL, NULL);
    dump_snap(t, "t100", 4);
    lc_tracker_update(t, detects, 2, 200, NULL, NULL);
    dump_snap(t, "t200", 4);
    lc_tracker_destroy(t);
}

static void scenario_match_order_contention(void)
{
    printf("=== match_order_contention ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){400, 4, 3, 1}, 1);
    lc_point_t a = {0.40f, 0.5f}, b = {0.60f, 0.5f};
    lc_point_t dets[2] = { a, b };
    lc_tracker_update(t, dets, 2, 100, NULL, NULL);
    dump_snap(t, "seed", 4);
    /* one equally-distant detect: lower id (earlier in greedy order) claims it */
    lc_point_t mid[1] = { {0.50f, 0.5f} };
    lc_tracker_update(t, mid, 1, 200, NULL, NULL);
    dump_snap(t, "contended", 4);
    /* both recover on the next frame */
    lc_point_t dets2[2] = { {0.50f, 0.5f}, {0.62f, 0.5f} };
    lc_tracker_update(t, dets2, 2, 300, NULL, NULL);
    dump_snap(t, "recovered", 4);
    lc_tracker_destroy(t);
}

static void scenario_confirm_gating(void)
{
    printf("=== confirm_gating ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 3}, 1);
    lc_point_t p = {0.5f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);
    dump_snap(t, "age1", 4);
    lc_tracker_update(t, &p, 1, 200, NULL, NULL);
    dump_snap(t, "age2", 4);
    lc_tracker_update(t, &p, 1, 300, NULL, NULL);
    dump_snap(t, "age3", 4);
    lc_tracker_destroy(t);
}

static void scenario_miss_retire(void)
{
    printf("=== miss_retire ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);
    lc_point_t p = {0.5f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);
    dump_snap(t, "born", 4);

    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;
    lc_point_t none[1];
    lc_tracker_update(t, none, 0, 200, &records, &n_records);
    dump_records(records, n_records);
    dump_snap(t, "miss1", 4);
    if (records) free_records_all(records, n_records);
    records = NULL; n_records = 0;

    lc_tracker_update(t, none, 0, 300, &records, &n_records);
    dump_records(records, n_records);
    dump_snap(t, "miss2", 4);
    if (records) free_records_all(records, n_records);
    records = NULL; n_records = 0;

    lc_tracker_update(t, none, 0, 400, &records, &n_records);
    dump_records(records, n_records);
    dump_snap(t, "retired", 4);
    if (records) free_records_all(records, n_records);
    records = NULL; n_records = 0;

    /* id continuity after retirement */
    lc_tracker_update(t, &p, 1, 500, NULL, NULL);
    dump_snap(t, "reborn", 4);
    lc_tracker_destroy(t);
}

static void scenario_record_subsampling(void)
{
    printf("=== record_subsampling ===\n");
    /* dur >= 5000ms -> 1000ms interval */
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 5, 1}, 1);
    uint32_t ts = 100;
    for (int i = 0; i < 25; ++i) {
        lc_point_t p = {0.5f, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }
    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;
    lc_point_t none[1];
    for (int i = 0; i < 6; ++i) {
        lc_tracker_update(t, none, 0, ts, &records, &n_records);
        ts += 100;
    }
    dump_records(records, n_records);
    if (records) free_records_all(records, n_records);
    records = NULL; n_records = 0;
    lc_tracker_destroy(t);

    /* 1000ms <= dur < 5000ms -> 333ms interval */
    t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 5, 1}, 1);
    ts = 100;
    for (int i = 0; i < 20; ++i) {
        lc_point_t p = {0.5f, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }
    for (int i = 0; i < 6; ++i) {
        lc_tracker_update(t, none, 0, ts, &records, &n_records);
        ts += 100;
    }
    dump_records(records, n_records);
    if (records) free_records_all(records, n_records);
    records = NULL; n_records = 0;
    lc_tracker_destroy(t);

    /* dur < 1000ms -> interval 0 (every point after seg start) */
    t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 5, 1}, 1);
    ts = 100;
    for (int i = 0; i < 4; ++i) {
        lc_point_t p = {0.5f, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }
    for (int i = 0; i < 6; ++i) {
        lc_tracker_update(t, none, 0, ts, &records, &n_records);
        ts += 100;
    }
    dump_records(records, n_records);
    if (records) free_records_all(records, n_records);
    records = NULL; n_records = 0;
    lc_tracker_destroy(t);
}

static void scenario_window_snapshot_chain(void)
{
    printf("=== window_snapshot_chain ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);
    lc_point_t p = {0.5f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);

    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;
    lc_tracker_window_snapshot(t, 200, &records, &n_records);
    dump_records(records, n_records);
    dump_snap(t, "after-window-1", 8);
    free_records_all(records, n_records);
    records = NULL; n_records = 0;

    p.x = 0.52f;
    lc_tracker_update(t, &p, 1, 300, NULL, NULL);
    lc_tracker_window_snapshot(t, 400, &records, &n_records);
    dump_records(records, n_records);
    dump_snap(t, "after-window-2", 8);
    free_records_all(records, n_records);
    records = NULL; n_records = 0;

    /* retirement chains onto the last window segment */
    lc_point_t none[1];
    for (int i = 0; i < 3; ++i) {
        lc_tracker_update(t, none, 0, (uint32_t)(500 + 100 * i), &records, &n_records);
        if (records) {
            dump_records(records, n_records);
            free_records_all(records, n_records);
        }
        records = NULL; n_records = 0;
    }
    dump_snap(t, "after-retire", 8);
    lc_tracker_destroy(t);
}

static void scenario_anti_bounce(void)
{
    printf("=== anti_bounce ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){500, 4, 2, 1}, 1);
    lc_line_cross_t *lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.0f, 0.5f);
    lc_point_t outside = {0.3f, 0.5f};
    lc_tracker_update(t, &outside, 1, 100, NULL, NULL);

    lc_point_t p;
    uint32_t ts = 200;
    p.x = 0.7f; p.y = 0.5f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    run_cross(t, lc, ts + 100, "step-in");
    dump_snap(t, "after-in", 4);
    ts += 100;

    p.x = 0.3f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    run_cross(t, lc, ts + 100, "step-out");
    dump_snap(t, "after-out", 4);
    ts += 100;

    p.x = 0.7f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    run_cross(t, lc, ts + 100, "step-in-2");
    ts += 100;

    p.x = 0.71f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    run_cross(t, lc, ts + 100, "step-same-side");
    dump_snap(t, "final", 4);

    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);
}

static void scenario_online_and_orientation(void)
{
    printf("=== online_and_orientation ===\n");
    /* point exactly on the line / starting on the line */
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){500, 4, 2, 1}, 1);
    lc_line_cross_t *lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.0f, 0.5f);
    lc_point_t p = {0.5f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);
    run_cross(t, lc, 200, "on-line-start");
    p.x = 0.7f;
    lc_tracker_update(t, &p, 1, 200, NULL, NULL);
    run_cross(t, lc, 300, "from-on-line");
    p.x = 0.3f;
    lc_tracker_update(t, &p, 1, 300, NULL, NULL);
    run_cross(t, lc, 400, "normal-out");
    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);

    /* outside anchor on the other side flips the reported direction */
    t = lc_tracker_create(&(lc_tracker_config_t){500, 4, 2, 1}, 1);
    lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.8f, 0.5f);
    p.x = 0.2f; p.y = 0.5f;
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);
    p.x = 0.8f;
    lc_tracker_update(t, &p, 1, 200, NULL, NULL);
    run_cross(t, lc, 300, "flipped-anchor");
    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);
}

static void scenario_crossing_uses_history(void)
{
    printf("=== crossing_uses_history ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){500, 4, 2, 1}, 1);
    lc_line_cross_t *lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.0f, 0.5f);
    lc_point_t p = {0.3f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);
    p.x = 0.7f;
    lc_tracker_update(t, &p, 1, 140, NULL, NULL);
    run_cross(t, lc, 190, "in-via-history");
    p.x = 0.3f;
    lc_tracker_update(t, &p, 1, 180, NULL, NULL);
    run_cross(t, lc, 240, "out-via-history");
    dump_track_rings(t, 1, 4, "trail-vs-history");
    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);
}

static void scenario_trail_first_point(void)
{
    printf("=== trail_first_point ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);
    lc_point_t p = {0.5f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);
    dump_track_rings(t, 1, 8, "first");
    lc_tracker_destroy(t);
}

static void scenario_trail_dense_frames(void)
{
    printf("=== trail_dense_frames ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 2, 1}, 1);
    uint32_t ts = 100;
    for (int i = 0; i < 20; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 50;
    }
    dump_snap(t, "moved", 16);
    dump_track_rings(t, 1, 16, "dense");
    lc_tracker_destroy(t);
}

static void scenario_trail_jitter_dedup(void)
{
    printf("=== trail_jitter_dedup ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);
    lc_point_t p = {0.505f, 0.5f};
    uint32_t ts = 100;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    for (int i = 0; i < 4; ++i) {
        ts += 100;
        p.x = (i % 2 == 0) ? 0.495f : 0.505f;
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    }
    dump_track_rings(t, 1, 8, "jitter");
    ts += 100;
    p.x = 0.505f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    dump_track_rings(t, 1, 8, "interval-500");
    ts += 100;
    p.x = 0.495f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    dump_track_rings(t, 1, 8, "jitter-again");
    ts += 400;
    p.x = 0.505f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    dump_track_rings(t, 1, 8, "interval-500-2");
    lc_tracker_destroy(t);
}

static void scenario_trail_multi_and_eviction(void)
{
    printf("=== trail_multi_and_eviction ===\n");
    /* ordered multi-point + k=8 eviction */
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);
    uint32_t ts = 100;
    for (int i = 0; i < 12; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }
    dump_track_rings(t, 1, 8, "k8-eviction");
    lc_tracker_destroy(t);

    /* k=16 eviction */
    t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 2, 1}, 1);
    ts = 100;
    for (int i = 0; i < 20; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }
    dump_track_rings(t, 1, 16, "k16-eviction");
    lc_tracker_destroy(t);

    /* two tracks, independent trails; second track jitters so its
     * trail is sparser */
    t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);
    ts = 100;
    for (int i = 0; i < 6; ++i) {
        lc_point_t a = {0.1f + 0.05f * (float)i, 0.2f};
        lc_point_t b = {(i % 2 == 0) ? 0.805f : 0.795f, 0.7f};
        lc_point_t dets[2] = { a, b };
        lc_tracker_update(t, dets, 2, ts, NULL, NULL);
        ts += 100;
    }
    dump_track_rings(t, 1, 8, "track-a");
    dump_track_rings(t, 2, 8, "track-b");
    lc_tracker_destroy(t);
}

static void scenario_capacity_and_clamp(void)
{
    printf("=== capacity_and_clamp ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);
    lc_point_t dets[70];
    for (int i = 0; i < 70; ++i) {
        dets[i].x = 0.01f * (float)(i + 1);
        dets[i].y = 0.5f;
    }
    lc_tracker_update(t, dets, 70, 100, NULL, NULL);
    dump_snap(t, "after-70-detects", 4);
    lc_tracker_update(t, dets, 70, 200, NULL, NULL);
    dump_snap(t, "after-second-frame", 4);
    lc_tracker_destroy(t);
}

static void scenario_multi_track_retire_order(void)
{
    printf("=== multi_track_retire_order ===\n");
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);
    lc_point_t detects[3] = { {0.1f, 0.1f}, {0.5f, 0.5f}, {0.9f, 0.9f} };
    lc_tracker_update(t, detects, 3, 100, NULL, NULL);
    dump_snap(t, "three-born", 4);
    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;
    lc_point_t none[1];
    for (int i = 0; i < 4; ++i) {
        lc_tracker_update(t, none, 0, (uint32_t)(200 + 100 * i), &records, &n_records);
        if (records) {
            dump_records(records, n_records);
            free_records_all(records, n_records);
        }
        records = NULL; n_records = 0;
    }
    dump_snap(t, "all-retired", 4);
    lc_tracker_destroy(t);
}

int main(void)
{
    scenario_serial_helpers();
    scenario_create_edges();
    scenario_greedy_matching();
    scenario_match_order_contention();
    scenario_confirm_gating();
    scenario_miss_retire();
    scenario_record_subsampling();
    scenario_window_snapshot_chain();
    scenario_anti_bounce();
    scenario_online_and_orientation();
    scenario_crossing_uses_history();
    scenario_trail_first_point();
    scenario_trail_dense_frames();
    scenario_trail_jitter_dedup();
    scenario_trail_multi_and_eviction();
    scenario_capacity_and_clamp();
    scenario_multi_track_retire_order();
    printf("=== end ===\n");
    return 0;
}
