#include <stdio.h>
#include <string.h>
#include "lc_tracker.h"
#include "lc_line_cross.h"

static int g_failures = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);       \
            g_failures++;                                               \
        }                                                               \
    } while (0)

#define CHECK_STR(actual, expected)                                     \
    do {                                                                \
        const char *a_ = (actual);                                      \
        const char *e_ = (expected);                                    \
        if (!a_ || strcmp(a_, e_) != 0) {                               \
            printf("FAIL %s:%d \"%s\" != \"%s\"\n", __FILE__,           \
                   __LINE__, a_ ? a_ : "(null)", e_);                   \
            g_failures++;                                               \
        }                                                               \
    } while (0)

typedef struct {
    uint32_t ids[LC_MAX_TRACKS];
    lc_point_t pos[LC_MAX_TRACKS];
    uint8_t age[LC_MAX_TRACKS];
    uint16_t count;
} track_snapshot_t;

static void snapshot_visitor(const lc_track_t *trk, void *user)
{
    track_snapshot_t *snap = (track_snapshot_t *)user;
    if (snap->count < LC_MAX_TRACKS) {
        snap->ids[snap->count] = trk->id;
        snap->pos[snap->count] = trk->last_pos;
        snap->age[snap->count] = trk->age;
        snap->count++;
    }
}

static void snapshot_tracks(const lc_tracker_t *t, track_snapshot_t *snap)
{
    memset(snap, 0, sizeof(*snap));
    lc_tracker_for_each_stable(t, snapshot_visitor, snap);
}

typedef struct {
    lc_point_t pts[LC_HISTORY_MAX];
    uint32_t   ts[LC_HISTORY_MAX];
    uint32_t   id;
    uint8_t    n;
    uint8_t    hist_used;
} trail_snap_track_t;

typedef struct {
    uint8_t            k;
    uint8_t            n_tracks;
    trail_snap_track_t tracks[4];
} trail_snap_t;

static int trail_feq(float a, float b)
{
    return (a - b) < 1e-4f && (b - a) < 1e-4f;
}

static void trail_visitor(const lc_track_t *trk, void *user)
{
    trail_snap_t *snap = (trail_snap_t *)user;
    if (snap->n_tracks >= 4) return;
    trail_snap_track_t *dst = &snap->tracks[snap->n_tracks];
    dst->id = trk->id;
    dst->n = trk->trail_used;
    dst->hist_used = trk->history_used;
    for (uint8_t i = 0; i < trk->trail_used; ++i) {
        uint8_t slot = (uint8_t)((trk->trail_head + snap->k - trk->trail_used + i) % snap->k);
        dst->pts[i] = trk->trail[slot];
        dst->ts[i] = trk->trail_ts[slot];
    }
    snap->n_tracks++;
}

static const trail_snap_track_t *trail_find(const trail_snap_t *snap, uint32_t id)
{
    for (uint8_t i = 0; i < snap->n_tracks; ++i) {
        if (snap->tracks[i].id == id) return &snap->tracks[i];
    }
    return NULL;
}

static void snap_trails(const lc_tracker_t *t, uint8_t k, trail_snap_t *snap)
{
    memset(snap, 0, sizeof(*snap));
    snap->k = k;
    lc_tracker_for_each_stable(t, trail_visitor, snap);
}

static void free_records(lc_track_record_t **records, uint16_t count)
{
    for (uint16_t i = 0; i < count; ++i) {
        LC_FREE(records[i]);
    }
    LC_FREE(records);
}

static void test_deterministic_greedy_matching(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);
    CHECK(t != NULL);

    lc_point_t detects[2] = { {0.10f, 0.10f}, {0.90f, 0.90f} };
    lc_tracker_update(t, detects, 2, 100, NULL, NULL);
    CHECK(lc_tracker_active_count(t) == 2);

    lc_tracker_update(t, detects, 2, 200, NULL, NULL);

    track_snapshot_t snap;
    snapshot_tracks(t, &snap);
    CHECK(snap.count == 2);
    int near_ok = 0, far_ok = 0;
    for (uint16_t i = 0; i < snap.count; ++i) {
        if (snap.pos[i].x < 0.5f) {
            near_ok = (snap.pos[i].x > 0.05f && snap.pos[i].x < 0.15f);
        } else {
            far_ok = (snap.pos[i].x > 0.85f && snap.pos[i].x < 0.95f);
        }
    }
    CHECK(near_ok);
    CHECK(far_ok);

    lc_tracker_destroy(t);
}

static void test_alternating_in_out_anti_bounce(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){500, 4, 2, 1}, 1);
    lc_line_cross_t *lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.0f, 0.5f);
    CHECK(t != NULL);
    CHECK(lc != NULL);

    lc_point_t outside = {0.3f, 0.5f};
    lc_tracker_update(t, &outside, 1, 100, NULL, NULL);

    uint32_t win_in = 0, win_out = 0, tot_in = 0, tot_out = 0;
    lc_point_t p;
    uint32_t ts = 200;

    p.x = 0.7f; p.y = 0.5f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL); ts += 100;
    lc_tracker_check_line_crossings(t, lc, ts, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_in == 1);
    CHECK(win_out == 0);

    p.x = 0.3f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL); ts += 100;
    lc_tracker_check_line_crossings(t, lc, ts, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_in == 1);
    CHECK(win_out == 1);

    p.x = 0.7f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL); ts += 100;
    lc_tracker_check_line_crossings(t, lc, ts, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_in == 2);
    CHECK(win_out == 1);
    CHECK(tot_in == 2);
    CHECK(tot_out == 1);

    p.x = 0.71f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL); ts += 100;
    win_in = 0; win_out = 0;
    lc_tracker_check_line_crossings(t, lc, ts, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_in == 0);
    CHECK(win_out == 0);

    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);
}

static void test_zero_detection_retirement(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);

    lc_point_t detect = {0.5f, 0.5f};
    lc_tracker_update(t, &detect, 1, 100, NULL, NULL);
    CHECK(lc_tracker_active_count(t) == 1);

    lc_point_t none[1];
    uint32_t ts = 200;
    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;

    lc_tracker_update(t, none, 0, ts, &records, &n_records); ts += 100;
    CHECK(records == NULL);
    CHECK(n_records == 0);
    CHECK(lc_tracker_active_count(t) == 1);
    if (records) free_records(records, n_records);

    lc_tracker_update(t, none, 0, ts, &records, &n_records); ts += 100;
    CHECK(lc_tracker_active_count(t) == 1);
    if (records) free_records(records, n_records);

    lc_tracker_update(t, none, 0, ts, &records, &n_records); ts += 100;
    CHECK(records != NULL);
    CHECK(n_records == 1);
    CHECK(records[0] != NULL);
    CHECK(records[0]->track_id == 1);
    CHECK(records[0]->seg_end_type == LC_SEG_DEPARTED);
    CHECK(lc_tracker_active_count(t) == 0);
    free_records(records, n_records);

    lc_tracker_destroy(t);
}

static void test_age_saturates_at_uint8_max(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);

    lc_point_t detect = {0.5f, 0.5f};
    uint32_t ts = 100;
    for (int i = 0; i < 300; ++i) {
        lc_tracker_update(t, &detect, 1, ts, NULL, NULL);
        ts += 100;
    }

    track_snapshot_t snap;
    snapshot_tracks(t, &snap);
    CHECK(snap.count == 1);
    CHECK(snap.age[0] == UINT8_MAX);
    CHECK(lc_tracker_active_count(t) == 1);

    lc_tracker_destroy(t);
}

static void test_record_growth_preserves_content(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);

    lc_point_t detects[3] = { {0.1f, 0.1f}, {0.5f, 0.5f}, {0.9f, 0.9f} };
    lc_tracker_update(t, detects, 3, 100, NULL, NULL);
    CHECK(lc_tracker_active_count(t) == 3);

    lc_point_t none[1];
    uint32_t ts = 200;
    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;

    int fired = 0;
    for (int i = 0; i < 4; ++i) {
        lc_tracker_update(t, none, 0, ts, &records, &n_records);
        ts += 100;
        if (records) {
            fired = 1;
            CHECK(n_records == 3);
            CHECK(records[0] != NULL);
            CHECK(records[1] != NULL);
            CHECK(records[2] != NULL);
            CHECK(records[0]->track_id == 1);
            CHECK(records[1]->track_id == 2);
            CHECK(records[2]->track_id == 3);
            CHECK(records[0]->seg_end_type == LC_SEG_DEPARTED);
            free_records(records, n_records);
        }
        records = NULL;
        n_records = 0;
    }
    CHECK(fired == 1);
    CHECK(lc_tracker_active_count(t) == 0);

    lc_tracker_destroy(t);
}

static void test_line_cross_edge_cases(void)
{
    CHECK(lc_line_cross_create(0.5f, 0.5f, 0.5f, 0.5f, 0.0f, 0.0f) == NULL);

    lc_line_cross_t *lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.8f, 0.5f);
    CHECK(lc != NULL);

    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){700, 4, 2, 1}, 1);
    lc_point_t inside = {0.2f, 0.5f};
    lc_tracker_update(t, &inside, 1, 100, NULL, NULL);
    lc_point_t outside = {0.8f, 0.5f};
    lc_tracker_update(t, &outside, 1, 200, NULL, NULL);

    uint32_t win_in = 0, win_out = 0, tot_in = 0, tot_out = 0;
    lc_tracker_check_line_crossings(t, lc, 300, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_in == 0);
    CHECK(win_out == 1);
    CHECK(tot_out == 1);

    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);
}

static void test_snapshot_window_keeps_tracks(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 4, 2, 1}, 1);

    lc_point_t detect = {0.5f, 0.5f};
    lc_tracker_update(t, &detect, 1, 100, NULL, NULL);

    lc_track_record_t **records = NULL;
    uint16_t n_records = 0;
    lc_tracker_window_snapshot(t, 200, &records, &n_records);
    CHECK(records != NULL);
    CHECK(n_records == 1);
    CHECK(records[0]->seg_end_type == LC_SEG_CROSSING);
    free_records(records, n_records);
    CHECK(lc_tracker_active_count(t) == 1);

    lc_tracker_destroy(t);
}

static void test_trail_first_point_immediate(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);

    lc_point_t detect = {0.5f, 0.5f};
    lc_tracker_update(t, &detect, 1, 100, NULL, NULL);

    trail_snap_t snap;
    snap_trails(t, 8, &snap);
    CHECK(snap.n_tracks == 1);
    const trail_snap_track_t *tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 1);
        CHECK(trail_feq(tr->pts[0].x, 0.5f));
        CHECK(trail_feq(tr->pts[0].y, 0.5f));
        CHECK(tr->ts[0] == 100);
    }

    lc_tracker_destroy(t);
}

static void test_trail_dense_frames_not_sampled(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 2, 1}, 1);

    uint32_t ts = 100;
    for (int i = 0; i < 20; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 50;
    }

    track_snapshot_t snap;
    snapshot_tracks(t, &snap);
    CHECK(snap.count == 1);
    CHECK(snap.pos[0].x > 1.03f && snap.pos[0].x < 1.07f);

    trail_snap_t tsnap;
    snap_trails(t, 16, &tsnap);
    CHECK(tsnap.n_tracks == 1);
    const trail_snap_track_t *tr = trail_find(&tsnap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->hist_used == 16);
        CHECK(tr->n == 10);
        for (uint8_t i = 0; i < 10; ++i) {
            CHECK(trail_feq(tr->pts[i].x, 0.1f + 0.1f * (float)i));
            CHECK(tr->ts[i] == (uint32_t)(100 + 100 * i));
        }
    }

    lc_tracker_destroy(t);
}

static void test_trail_stationary_jitter_dedup_500ms(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);

    lc_point_t p = {0.505f, 0.5f};
    uint32_t ts = 100;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);

    for (int i = 0; i < 4; ++i) {
        ts += 100;
        p.x = (i % 2 == 0) ? 0.495f : 0.505f;
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    }

    trail_snap_t snap;
    snap_trails(t, 8, &snap);
    const trail_snap_track_t *tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 1);
        CHECK(tr->ts[0] == 100);
    }

    ts += 100;
    p.x = 0.505f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    CHECK(lc_tracker_active_count(t) == 1);
    snap_trails(t, 8, &snap);
    tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 2);
        CHECK(tr->ts[0] == 100);
        CHECK(tr->ts[1] == 600);
    }

    ts += 100;
    p.x = 0.495f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    snap_trails(t, 8, &snap);
    tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 2);
    }

    ts += 400;
    p.x = 0.505f;
    lc_tracker_update(t, &p, 1, ts, NULL, NULL);
    snap_trails(t, 8, &snap);
    tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 3);
        CHECK(tr->ts[2] == 1100);
    }

    lc_tracker_destroy(t);
}

static void test_trail_moving_multi_point_ordered(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);

    uint32_t ts = 100;
    for (int i = 0; i < 6; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }

    trail_snap_t snap;
    snap_trails(t, 8, &snap);
    const trail_snap_track_t *tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 6);
        for (uint8_t i = 0; i < 6; ++i) {
            CHECK(trail_feq(tr->pts[i].x, 0.1f + 0.05f * (float)i));
            CHECK(trail_feq(tr->pts[i].y, 0.5f));
            CHECK(tr->ts[i] == (uint32_t)(100 + 100 * i));
        }
    }

    lc_tracker_destroy(t);
}

static void test_trail_capacity_eviction_k8(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);

    uint32_t ts = 100;
    for (int i = 0; i < 12; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }

    trail_snap_t snap;
    snap_trails(t, 8, &snap);
    const trail_snap_track_t *tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 8);
        CHECK(tr->ts[0] == 500);
        CHECK(trail_feq(tr->pts[0].x, 0.1f + 0.05f * 4.0f));
        CHECK(tr->ts[7] == 1200);
        CHECK(trail_feq(tr->pts[7].x, 0.1f + 0.05f * 11.0f));
        for (uint8_t i = 1; i < 8; ++i) {
            CHECK(tr->ts[i] > tr->ts[i - 1]);
        }
    }

    lc_tracker_destroy(t);
}

static void test_trail_capacity_eviction_k16(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 16, 2, 1}, 1);

    uint32_t ts = 100;
    for (int i = 0; i < 20; ++i) {
        lc_point_t p = {0.1f + 0.05f * (float)i, 0.5f};
        lc_tracker_update(t, &p, 1, ts, NULL, NULL);
        ts += 100;
    }

    trail_snap_t snap;
    snap_trails(t, 16, &snap);
    const trail_snap_track_t *tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 16);
        CHECK(tr->ts[0] == 500);
        CHECK(trail_feq(tr->pts[0].x, 0.1f + 0.05f * 4.0f));
        CHECK(tr->ts[15] == 2000);
        CHECK(trail_feq(tr->pts[15].x, 0.1f + 0.05f * 19.0f));
    }

    lc_tracker_destroy(t);
}

static void test_trail_tracks_independent(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){150, 8, 2, 1}, 1);

    uint32_t ts = 100;
    for (int i = 0; i < 6; ++i) {
        lc_point_t a = {0.1f + 0.05f * (float)i, 0.2f};
        lc_point_t b = {(i % 2 == 0) ? 0.805f : 0.795f, 0.7f};
        lc_point_t dets[2] = {a, b};
        lc_tracker_update(t, dets, 2, ts, NULL, NULL);
        ts += 100;
    }

    trail_snap_t snap;
    snap_trails(t, 8, &snap);
    CHECK(snap.n_tracks == 2);
    const trail_snap_track_t *ta = trail_find(&snap, 1);
    const trail_snap_track_t *tb = trail_find(&snap, 2);
    CHECK(ta != NULL);
    CHECK(tb != NULL);
    if (ta && tb) {
        CHECK(ta->n == 6);
        for (uint8_t i = 0; i < 6; ++i) {
            CHECK(trail_feq(ta->pts[i].y, 0.2f));
            CHECK(ta->pts[i].x < 0.5f);
        }
        CHECK(tb->n == 2);
        CHECK(tb->ts[0] == 100);
        CHECK(tb->ts[1] == 600);
        for (uint8_t i = 0; i < 2; ++i) {
            CHECK(trail_feq(tb->pts[i].y, 0.7f));
            CHECK(tb->pts[i].x > 0.5f);
        }
    }

    lc_tracker_destroy(t);
}

static void test_crossing_uses_history_not_trail(void)
{
    lc_tracker_t *t = lc_tracker_create(&(lc_tracker_config_t){500, 4, 2, 1}, 1);
    lc_line_cross_t *lc = lc_line_cross_create(0.5f, 0.0f, 0.5f, 1.0f, 0.0f, 0.5f);
    CHECK(t != NULL);
    CHECK(lc != NULL);

    lc_point_t p = {0.3f, 0.5f};
    lc_tracker_update(t, &p, 1, 100, NULL, NULL);

    p.x = 0.7f;
    lc_tracker_update(t, &p, 1, 140, NULL, NULL);

    uint32_t win_in = 0, win_out = 0, tot_in = 0, tot_out = 0;
    lc_tracker_check_line_crossings(t, lc, 190, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_in == 1);
    CHECK(tot_in == 1);

    p.x = 0.3f;
    lc_tracker_update(t, &p, 1, 180, NULL, NULL);
    win_in = 0; win_out = 0;
    lc_tracker_check_line_crossings(t, lc, 240, &win_in, &win_out, &tot_in, &tot_out, NULL, 0, NULL);
    CHECK(win_out == 1);
    CHECK(tot_out == 1);

    trail_snap_t snap;
    snap_trails(t, 4, &snap);
    const trail_snap_track_t *tr = trail_find(&snap, 1);
    CHECK(tr != NULL);
    if (tr) {
        CHECK(tr->n == 1);
        CHECK(trail_feq(tr->pts[0].x, 0.3f));
        CHECK(tr->ts[0] == 100);
    }

    lc_line_cross_destroy(lc);
    lc_tracker_destroy(t);
}

int main(void)
{
    test_deterministic_greedy_matching();
    test_alternating_in_out_anti_bounce();
    test_zero_detection_retirement();
    test_age_saturates_at_uint8_max();
    test_record_growth_preserves_content();
    test_line_cross_edge_cases();
    test_snapshot_window_keeps_tracks();
    test_trail_first_point_immediate();
    test_trail_dense_frames_not_sampled();
    test_trail_stationary_jitter_dedup_500ms();
    test_trail_moving_multi_point_ordered();
    test_trail_capacity_eviction_k8();
    test_trail_capacity_eviction_k16();
    test_trail_tracks_independent();
    test_crossing_uses_history_not_trail();

    if (g_failures != 0) {
        printf("%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("all lc engine tests passed\n");
    return 0;
}
