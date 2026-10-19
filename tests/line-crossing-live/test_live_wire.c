
#include "test_live.h"
#include "live_stub.h"
#include "ref_decoder.h"
#include "lc_lvn4.h"

static live_det_t det_c(float cx, float cy)
{
    live_det_t d;
    d.x = cx - 0.02f;
    d.y = cy - 0.02f;
    d.w = 0.04f;
    d.h = 0.04f;
    d.conf = 0.9f;
    d.class_index = 1u;
    return d;
}

static int decode_pkt(const live_env_t *e, uint32_t idx, rd_view_t *v)
{
    memset(v, 0, sizeof(*v));
    return rd_decode(live_rec_bytes(e->rec, idx), live_rec_len(e->rec, idx), 2u, v);
}

static void feed_row(live_env_t *e, uint32_t t, float y, uint32_t n, float x0, float dx)
{
    live_det_t dets[64];
    uint32_t i;
    for (i = 0; i < n; i++) dets[i] = det_c(x0 + dx * (float)i, y);
    live_env_frame(e, t, dets, n);
}

static void test_arm_validation(void)
{
    live_env_t *e = live_env_new();
    CHECK(e != NULL);
    lc_lvn4_init(&e->prod, &e->bus, NULL, NULL);
    lc_lvn4_grant_t g = {1u, 312u, 1u};
    CHECK_EQ_I(lc_lvn4_arm(&e->prod, &g), -1);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNAVAILABLE_NO_CAPABILITY);
    live_env_free(e);

    live_env_t *e2 = live_env_new();
    CHECK(e2 != NULL);
    CHECK_EQ_I(lc_lvn4_arm(&e2->prod, NULL), -1);
    CHECK_EQ_I(lc_lvn4_state(&e2->prod), LC_LVN4_STATE_UNAVAILABLE_BAD_GRANT);

    g.session_generation = 0u;
    CHECK_EQ_I(lc_lvn4_arm(&e2->prod, &g), -1);
    g.session_generation = 1u;
    g.live_track_max = 0u;
    CHECK_EQ_I(lc_lvn4_arm(&e2->prod, &g), -1);
    g.live_track_max = 65u;
    CHECK_EQ_I(lc_lvn4_arm(&e2->prod, &g), -1);
    g.live_track_max = 1u;
    g.live_publish_max = 311u;
    CHECK_EQ_I(lc_lvn4_arm(&e2->prod, &g), -1);
    CHECK_EQ_I(lc_lvn4_state(&e2->prod), LC_LVN4_STATE_UNAVAILABLE_BAD_GRANT);
    g.live_publish_max = 312u;
    CHECK_EQ_I(lc_lvn4_arm(&e2->prod, &g), 0);
    CHECK_EQ_I(lc_lvn4_state(&e2->prod), LC_LVN4_STATE_ARMED);
    live_env_free(e2);

    live_env_t *e3 = live_env_new();
    CHECK(e3 != NULL);
    lc_lvn4_grant_t g64 = {9u, 9007u, 64u};
    CHECK_EQ_I(lc_lvn4_arm(&e3->prod, &g64), -1);
    CHECK_EQ_I(lc_lvn4_state(&e3->prod), LC_LVN4_STATE_UNAVAILABLE_BAD_GRANT);
    g64.live_publish_max = 9008u;
    CHECK_EQ_I(lc_lvn4_arm(&e3->prod, &g64), 0);
    live_env_free(e3);
}

static void test_session_reuse(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 7u, 16u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    uint32_t before = live_rec_count(e->rec);
    CHECK(before >= 3u);

    lc_lvn4_disarm(&e->prod);
    lc_lvn4_grant_t g = {7u, 2288u, 16u};
    CHECK_EQ_I(lc_lvn4_arm(&e->prod, &g), -1);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNAVAILABLE_SESSION_REUSED);

    g.session_generation = 8u;
    CHECK_EQ_I(lc_lvn4_arm(&e->prod, &g), 0);
    CHECK_EQ_I(e->prod.through_seq, 0u);
    CHECK_EQ_I(e->prod.cumulative_total, 0u);
    feed_row(e, 500u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 700u, 0.60f, 1u, 0.5f, 0.0f);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n > before);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.events[0].seq, 2u);
    printf("wire/session-reuse done\n");
}

static void test_first_packets_golden(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 1u, 4u);
    feed_row(e, 100u, 0.40f, 0u, 0.5f, 0.0f);

    CHECK_EQ_I(live_rec_count(e->rec), 2u);
    static const uint8_t golden_kind1[48] = {
        0x4c, 0x56, 0x4e, 0x34, 0x01, 0x00, 0x01, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t golden_kind2[48] = {
        0x4c, 0x56, 0x4e, 0x34, 0x01, 0x00, 0x02, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    CHECK_EQ_I(live_rec_len(e->rec, 0u), 48u);
    if (live_rec_count(e->rec) == 2u && live_rec_len(e->rec, 0u) == 48u) {
        CHECK(memcmp(live_rec_bytes(e->rec, 0u), golden_kind1, 48u) == 0);
    }
    CHECK_EQ_I(live_rec_len(e->rec, 1u), 48u);
    if (live_rec_count(e->rec) == 2u && live_rec_len(e->rec, 1u) == 48u) {
        CHECK(memcmp(live_rec_bytes(e->rec, 1u), golden_kind2, 48u) == 0);
    }

    rd_view_t v;
    CHECK_EQ_I(decode_pkt(e, 0u, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.record_count, 0u);
    CHECK_EQ_I(v.event_through_seq, 0u);
    CHECK_EQ_I(v.cumulative_event_total, 0u);
    CHECK_EQ_I(v.cumulative_source_gap, 0u);
    CHECK_EQ_I(v.flags, 0x4u);
    CHECK_EQ_I(v.config_generation, 1u);
    CHECK_EQ_I(decode_pkt(e, 1u, &v), 0);
    CHECK_EQ_I(v.kind, 2u);
    CHECK_EQ_I(v.record_count, 0u);

    feed_row(e, 200u, 0.40f, 0u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), 4u);
    CHECK_EQ_I(decode_pkt(e, 2u, &v), 0);
    CHECK_EQ_I(v.packet_seq, 3u);
    CHECK_EQ_I(v.flags, 0u);
    printf("wire/first-packets-golden done\n");
}

static void test_crossing_in_out(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 11u, 4u);
    feed_row(e, 1000u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 1200u, 0.60f, 1u, 0.5f, 0.0f);
    feed_row(e, 1400u, 0.40f, 1u, 0.5f, 0.0f);

    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= 6u);
    CHECK_EQ_I(decode_pkt(e, 2u, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.events[0].seq, 1u);
    CHECK_EQ_I(v.events[0].direction, 1u);
    CHECK_EQ_I(v.events[0].track_id, 1u);
    CHECK_EQ_I(v.events[0].ts_ms, 1200u);
    CHECK_EQ_I(v.events[0].x_q8, LIVE_Q8(0.5f));
    CHECK_EQ_I(v.events[0].y_q8, LIVE_Q8(0.6f));
    CHECK_EQ_I(v.event_through_seq, 1u);
    CHECK_EQ_I(v.cumulative_event_total, 1u);
    CHECK_EQ_I(v.flags, 0u);
    CHECK_EQ_I(decode_pkt(e, 3u, &v), 0);
    CHECK_EQ_I(v.kind, 2u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.tracks[0].track_id, 1u);
    CHECK_EQ_I(v.tracks[0].class_index, 1u);
    CHECK_EQ_I(v.tracks[0].state, 1u);
    CHECK_EQ_I(v.tracks[0].flags, 0u);
    CHECK_EQ_I(v.tracks[0].point_count, 2u);
    CHECK_EQ_I(v.tracks[0].pts[0].ts_ms, 1000u);
    CHECK_EQ_I(v.tracks[0].pts[0].x_q16, LIVE_Q16(0.5f));
    CHECK_EQ_I(v.tracks[0].pts[0].y_q16, LIVE_Q16(0.4f));
    CHECK_EQ_I(v.tracks[0].pts[1].ts_ms, 1200u);
    CHECK_EQ_I(v.tracks[0].pts[1].y_q16, LIVE_Q16(0.6f));

    CHECK_EQ_I(decode_pkt(e, 4u, &v), 0);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.events[0].seq, 2u);
    CHECK_EQ_I(v.events[0].direction, 2u);
    CHECK_EQ_I(v.event_through_seq, 2u);
    CHECK_EQ_I(v.cumulative_event_total, 2u);
    CHECK_EQ_I(v.flags, 0u);

    CHECK_EQ_I(e->bus.total_in, 1u);
    CHECK_EQ_I(e->bus.total_out, 1u);
    printf("wire/crossing-in-out done\n");
}

static void test_sixteen_crossings(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 21u, 64u);
    feed_row(e, 100u, 0.40f, 16u, 0.08f, 0.055f);
    feed_row(e, 300u, 0.60f, 16u, 0.08f, 0.055f);

    rd_view_t v;
    CHECK_EQ_I(decode_pkt(e, 2u, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.record_count, 16u);
    CHECK_EQ_I(v.total_len, 304u);
    CHECK_EQ_I(v.event_through_seq, 16u);
    CHECK_EQ_I(v.cumulative_event_total, 16u);
    CHECK_EQ_I(v.cumulative_source_gap, 0u);
    CHECK_EQ_I(v.flags, 0u);
    uint32_t i;
    for (i = 0; i < 16u; i++) {
        CHECK_EQ_I(v.events[i].seq, i + 1u);
        CHECK_EQ_I(v.events[i].direction, 1u);
    }
    CHECK_EQ_I(e->bus.total_in, 16u);
    live_env_free(e);
}

static void test_seventeen_crossings_truncation(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 22u, 64u);
    feed_row(e, 100u, 0.40f, 17u, 0.06f, 0.05f);
    feed_row(e, 300u, 0.60f, 17u, 0.06f, 0.05f);

    rd_view_t v;
    CHECK_EQ_I(decode_pkt(e, 2u, &v), 0);
    CHECK_EQ_I(v.record_count, 16u);
    CHECK_EQ_I(v.total_len, 304u);
    CHECK_EQ_I(v.event_through_seq, 17u);
    CHECK_EQ_I(v.cumulative_event_total, 17u);
    CHECK_EQ_I(v.cumulative_source_gap, 1u);
    CHECK_EQ_I(v.flags, 0x1u);
    uint32_t i;
    uint32_t seen = 0u;
    for (i = 0; i < 16u; i++) {
        CHECK_EQ_I(v.events[i].seq, i + 1u);
        seen += v.events[i].track_id != 0u ? 1u : 0u;
    }
    CHECK_EQ_I(seen, 16u);
    CHECK_EQ_I(e->prod.st.truncated_events, 1u);
    CHECK_EQ_I(e->bus.total_in, 17u);
    live_env_free(e);
}

static void test_zero_tracks_clear(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 31u, 8u);
    feed_row(e, 100u, 0.30f, 1u, 0.5f, 0.0f);
    uint32_t t;
    for (t = 300u; t <= 1600u; t += 200u) {
        feed_row(e, t, 0.30f, 0u, 0.5f, 0.0f);
    }
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= 2u);
    CHECK_EQ_I(decode_pkt(e, n - 1u, &v), 0);
    CHECK_EQ_I(v.kind, 2u);
    CHECK_EQ_I(v.record_count, 0u);
    CHECK_EQ_I(e->prod.st.track_cleared, 2u);
    live_env_free(e);
}

static void test_sixty_four_tracks_full_closure(void)
{
    live_env_t *e = live_env_new();
    lc_bus_config_t cfg = e->bus.cfg;
    cfg.track_history_k = 16u;
    CHECK_EQ_I(lcbus_apply_config(&e->bus, &cfg), 0);
    live_env_arm(e, 41u, 64u);

    uint32_t f;
    for (f = 0; f < 17u; f++) {
        live_det_t dets[64];
        uint32_t i;
        for (i = 0; i < 64u; i++) {
            dets[i] = det_c(0.02f + 0.015f * (float)i, 0.30f);
        }
        live_env_frame(e, 1000u + f * 100u, dets, 64u);
    }

    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= 2u);
    CHECK_EQ_I(decode_pkt(e, n - 1u, &v), 0);
    CHECK_EQ_I(v.kind, 2u);
    CHECK_EQ_I(v.record_count, 64u);
    CHECK_EQ_I(v.total_len, 9008u);
    uint32_t i;
    uint32_t ids[64];
    for (i = 0; i < 64u; i++) {
        ids[i] = v.tracks[i].track_id;
        CHECK(v.tracks[i].track_id != 0u);
        CHECK_EQ_I(v.tracks[i].point_count, 16u);
        CHECK_EQ_I(v.tracks[i].state, 1u);
        uint32_t j;
        for (j = 0; j < 16u; j++) {
            CHECK_EQ_I(v.tracks[i].pts[j].ts_ms, 1000u + (j + 1u) * 100u);
        }
    }
    for (i = 0; i < 64u; i++) {
        uint32_t j;
        for (j = i + 1u; j < 64u; j++) {
            if (ids[i] == ids[j]) { CHECK(0); }
        }
    }
    live_env_free(e);
}

static void test_track_capacity_fail_closed(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 51u, 1u);
    feed_row(e, 100u, 0.30f, 1u, 0.4f, 0.0f);
    uint32_t n0 = live_rec_count(e->rec);
    CHECK(n0 >= 2u);
    feed_row(e, 300u, 0.30f, 2u, 0.4f, 0.2f);
    CHECK_EQ_I(live_rec_count(e->rec), n0);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNAVAILABLE_TRACK_CAPACITY);
    feed_row(e, 500u, 0.30f, 1u, 0.4f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), n0);
    live_env_free(e);
}

static void test_gap_loss_unknown(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 61u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);

    uint8_t buf[64];
    uint32_t len = live_gap_event(buf, sizeof(buf), 900u, 400u, 0x2u, 0xFFFFFFFFu);
    live_env_raw(e, buf, len);
    CHECK_EQ_I(e->prod.st.gap_events, 1u);
    CHECK_EQ_I(e->prod.loss_unknown_latch, 1u);

    feed_row(e, 500u, 0.40f, 1u, 0.5f, 0.0f);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.flags, 0x2u);
    CHECK_EQ_I(v.cumulative_source_gap, 0u);

    len = live_gap_event(buf, sizeof(buf), 901u, 600u, 0x1u, 3u);
    live_env_raw(e, buf, len);
    CHECK_EQ_I(e->prod.loss_unknown_latch, 1u);
    feed_row(e, 700u, 0.40f, 1u, 0.5f, 0.0f);
    n = live_rec_count(e->rec);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.flags, 0x2u);
    live_env_free(e);
}

static void test_rebind_resync(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 71u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(e->prod.through_seq, 1u);

    e->model_gen = 8u;
    uint8_t buf[64];
    uint32_t len = live_model_changed(buf, sizeof(buf), 901u, 350u);
    live_env_raw(e, buf, len);
    feed_row(e, 500u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 700u, 0.60f, 1u, 0.5f, 0.0f);

    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.event_through_seq, 2u);
    CHECK_EQ_I(v.cumulative_event_total, 2u);
    CHECK_EQ_I(v.events[0].seq, 2u);
    uint32_t i;
    int saw_resync = 0;
    for (i = 0; i < n; i++) {
        if (decode_pkt(e, i, &v) == 0 && (v.flags & 0x4u) != 0u) saw_resync = 1;
    }
    CHECK(saw_resync);
    live_env_free(e);
}

static void test_config_generation_change(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 81u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);

    lc_bus_config_t cfg = e->bus.cfg;
    cfg.line_y1_permille = 400u;
    cfg.line_y2_permille = 400u;
    lcbus_cfg_txn_t txn;
    CHECK_EQ_I(lcbus_txn_prepare_config(&e->bus, &cfg, &txn), LCBUS_TXN_OK);
    CHECK_EQ_I(lcbus_txn_commit_config(&e->bus, &txn), LCBUS_TXN_OK);
    CHECK_EQ_I(e->bus.config_generation, 2u);

    feed_row(e, 300u, 0.30f, 1u, 0.5f, 0.0f);
    feed_row(e, 500u, 0.50f, 1u, 0.5f, 0.0f);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.config_generation, 2u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.events[0].direction, 1u);
    live_env_free(e);
}

static void test_gate_paused_accounts(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 91u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    uint32_t n_open = live_rec_count(e->rec);
    CHECK(n_open >= 2u);

    lc_lvn4_set_gate(&e->prod, LC_LVN4_GATE_PAUSED);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    feed_row(e, 500u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), n_open);
    CHECK_EQ_I(e->prod.cumulative_total, 1u);
    CHECK_EQ_I(e->prod.through_seq, 1u);
    CHECK_EQ_I(e->prod.cumulative_gap, 1u);
    CHECK_EQ_I(e->prod.st.gate_held_events, 1u);
    live_env_idle(e, 1000u);
    CHECK_EQ_I(live_rec_count(e->rec), n_open);

    lc_lvn4_set_gate(&e->prod, LC_LVN4_GATE_OPEN);
    feed_row(e, 800u, 0.40f, 1u, 0.5f, 0.0f);
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= n_open + 2u);
    rd_view_t v;
    CHECK_EQ_I(decode_pkt(e, n_open, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.events[0].seq, 2u);
    CHECK_EQ_I(v.event_through_seq, 2u);
    CHECK_EQ_I(v.cumulative_event_total, 2u);
    CHECK_EQ_I(v.cumulative_source_gap, 1u);
    CHECK_EQ_I(v.flags, 0x5u);
    CHECK_EQ_I(e->bus.total_in + e->bus.total_out, 2u);
    live_env_free(e);
}

static void test_gate_unknown_loss(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 92u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    uint32_t n_open = live_rec_count(e->rec);

    lc_lvn4_set_gate(&e->prod, LC_LVN4_GATE_UNKNOWN);
    feed_row(e, 300u, 0.40f, 0u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), n_open);
    lc_lvn4_set_gate(&e->prod, LC_LVN4_GATE_OPEN);
    feed_row(e, 500u, 0.40f, 0u, 0.5f, 0.0f);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= n_open + 2u);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.flags, 0x6u);
    CHECK_EQ_I(v.cumulative_source_gap, 0u);
    live_env_free(e);
}

static void test_publish_failure_gap(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 93u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), 2u);

    live_rec_fail_next(e->rec, -5, 1);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(e->prod.st.publish_failures, 1u);
    CHECK_EQ_I(e->prod.cumulative_gap, 1u);
    CHECK_EQ_I(e->prod.cumulative_total, 1u);
    CHECK_EQ_I(live_rec_count(e->rec), 3u);

    rd_view_t v;
    CHECK_EQ_I(decode_pkt(e, 2u, &v), 0);
    CHECK_EQ_I(v.kind, 2u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.event_through_seq, 1u);
    CHECK_EQ_I(v.cumulative_event_total, 1u);
    CHECK_EQ_I(v.cumulative_source_gap, 1u);
    CHECK_EQ_I(v.flags, 0x1u);

    feed_row(e, 500u, 0.40f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(decode_pkt(e, 3u, &v), 0);
    CHECK_EQ_I(v.kind, 1u);
    CHECK_EQ_I(v.record_count, 1u);
    CHECK_EQ_I(v.events[0].seq, 2u);
    CHECK_EQ_I(v.event_through_seq, 2u);
    CHECK_EQ_I(v.cumulative_source_gap, 1u);
    CHECK_EQ_I(v.flags, 0u);
    live_env_free(e);
}

static void test_exhaustion_total(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 94u, 8u);
    lcbus_live_facts_t f;
    memset(&f, 0, sizeof(f));
    f.kind_frame = 1;
    f.frame_complete = 1;
    f.mono_ms = 10u;
    f.frame_in = 0xFFFFFFFFu;
    lc_lvn4_observe(&e->prod, &f);
    CHECK_EQ_I(e->prod.through_seq, 0xFFFFFFFFu);
    CHECK_EQ_I(e->prod.cumulative_total, 0xFFFFFFFFu);
    CHECK_EQ_I(e->prod.cumulative_gap, 0xFFFFFFFFu);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_ARMED);

    uint32_t n0 = live_rec_count(e->rec);
    rd_view_t v;
    CHECK_EQ_I(decode_pkt(e, n0 - 2u, &v), 0);
    CHECK_EQ_I(v.event_through_seq, 0xFFFFFFFFu);

    f.frame_in = 1u;
    lc_lvn4_observe(&e->prod, &f);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNAVAILABLE_EXHAUSTED);
    CHECK_EQ_I(live_rec_count(e->rec), n0);
    live_env_free(e);
}

static void test_packet_seq_exhaustion(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 95u, 8u);
    e->prod.packet_seq = 0xFFFFFFFFu;
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNAVAILABLE_EXHAUSTED);
    CHECK_EQ_I(live_rec_count(e->rec), 0u);
    live_env_free(e);
}

static void test_disarmed_and_unarmed(void)
{
    live_env_t *e = live_env_new();
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), 0u);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNARMED);

    live_env_arm(e, 96u, 8u);
    lc_lvn4_disarm(&e->prod);
    feed_row(e, 500u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 700u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), 0u);
    CHECK_EQ_I(e->prod.through_seq, 0u);
    live_env_free(e);
}

static void test_lost_capability_reset(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 98u, 8u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    uint32_t before = live_rec_count(e->rec);
    CHECK(before >= 2u);
    live_rec_fail_next(e->rec, LC_RET_UNAUTHORIZED, 1u);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(lc_lvn4_state(&e->prod), LC_LVN4_STATE_UNAVAILABLE_NO_CAPABILITY);
    CHECK_EQ_I(e->prod.session_generation, 98u);
    CHECK_EQ_I(e->prod.live_publish_max, 0u);
    CHECK_EQ_I(e->prod.live_track_max, 0u);
    CHECK_EQ_I(e->prod.packet_seq, 0u);
    CHECK_EQ_I(e->prod.through_seq, 0u);
    CHECK_EQ_I(e->prod.cumulative_total, 0u);
    CHECK_EQ_I(e->prod.cumulative_gap, 0u);
    CHECK_EQ_I(live_rec_count(e->rec), before);
    feed_row(e, 500u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 700u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), before);
    lc_lvn4_grant_t grant = {98u, 2288u, 16u};
    CHECK_EQ_I(lc_lvn4_arm(&e->prod, &grant), -1);
    grant.session_generation = 99u;
    CHECK_EQ_I(lc_lvn4_arm(&e->prod, &grant), 0);
    CHECK_EQ_I(e->prod.packet_seq, 0u);
    CHECK_EQ_I(e->prod.through_seq, 0u);
    CHECK_EQ_I(e->prod.cumulative_total, 0u);
    live_env_free(e);
}

static void test_decoder_negatives(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 97u, 4u);
    feed_row(e, 100u, 0.40f, 1u, 0.5f, 0.0f);
    feed_row(e, 300u, 0.60f, 1u, 0.5f, 0.0f);
    CHECK_EQ_I(live_rec_count(e->rec), 4u);

    uint8_t buf[512];
    uint8_t keep[512];
    rd_view_t v;
    uint32_t len1 = live_rec_len(e->rec, 2u);
    CHECK_EQ_I(len1, 64u);
    if (live_rec_count(e->rec) != 4u || len1 != 64u) {
        printf("decoder-negatives skipped (packets=%u)\n", live_rec_count(e->rec));
        live_env_free(e);
        return;
    }
    memcpy(buf, live_rec_bytes(e->rec, 2u), len1);

    buf[0] = 0x4d;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_MAGIC);
    buf[0] = 0x4c;
    buf[4] = 2u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_VERSION);
    buf[4] = 1u;
    buf[6] = 3u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_KIND);
    buf[6] = 1u;
    buf[44] = 1u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_RESERVED);
    buf[44] = 0u;
    buf[41] = 0x20u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_FLAGS);
    buf[41] = 0u;
    buf[12] = 0u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_SEQ);
    buf[12] = 1u;
    buf[32] = 0u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_SEQ);
    buf[32] = 1u;

    CHECK(rd_decode(buf, len1 - 1u, 2u, &v) == RD_ERR_LEN);
    CHECK(rd_decode(buf, len1 + 1u, 2u, &v) == RD_ERR_LEN);

    memcpy(keep, buf, len1);
    buf[48] = 0u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_SEQ);
    memcpy(buf, keep, len1);
    buf[48] = 2u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_SEQ);
    memcpy(buf, keep, len1);
    buf[52] = 0u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_RECORD);
    memcpy(buf, keep, len1);
    buf[60] = 3u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_DIRECTION);
    memcpy(buf, keep, len1);
    buf[61] = 0x2u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_FLAGS);
    memcpy(buf, keep, len1);
    buf[36] = 17u;
    CHECK(rd_decode(buf, len1, 2u, &v) == RD_ERR_COUNT);
    memcpy(buf, keep, len1);
    CHECK(rd_decode(buf, len1, 2u, &v) == 0);

    uint32_t len2 = live_rec_len(e->rec, 3u);
    CHECK_EQ_I(len2, 76u);
    memcpy(buf, live_rec_bytes(e->rec, 3u), len2);
    memcpy(keep, buf, len2);
    buf[56] = 2u;
    CHECK(rd_decode(buf, len2, 2u, &v) == RD_ERR_STATE);
    memcpy(buf, keep, len2);
    buf[57] = 1u;
    CHECK(rd_decode(buf, len2, 2u, &v) == RD_ERR_FLAGS);
    memcpy(buf, keep, len2);
    buf[52] = 17u;
    CHECK(rd_decode(buf, len2, 2u, &v) == RD_ERR_RECORD);
    memcpy(buf, keep, len2);
    buf[54] = 0xFFu;
    buf[55] = 0xFFu;
    CHECK(rd_decode(buf, len2, 2u, &v) == 0);
    memcpy(buf, keep, len2);
    buf[54] = 2u;
    buf[55] = 0u;
    CHECK(rd_decode(buf, len2, 2u, &v) == RD_ERR_CLASS);
    memcpy(buf, keep, len2);
    CHECK(rd_decode(buf, len2, 0u, &v) == RD_ERR_CLASS);
    memcpy(buf, keep, len2);
    CHECK(rd_decode(buf, len2, 2u, &v) == 0);
    CHECK(rd_decode(buf, len2 + 1u, 2u, &v) == RD_ERR_LEN);

    live_env_free(e);
}

int g_pass;
int g_fail;

int main(void)
{
    g_pass = 0;
    g_fail = 0;
    test_arm_validation();
    test_session_reuse();
    test_first_packets_golden();
    test_crossing_in_out();
    test_sixteen_crossings();
    test_seventeen_crossings_truncation();
    test_zero_tracks_clear();
    test_sixty_four_tracks_full_closure();
    test_track_capacity_fail_closed();
    test_gap_loss_unknown();
    test_rebind_resync();
    test_config_generation_change();
    test_gate_paused_accounts();
    test_gate_unknown_loss();
    test_publish_failure_gap();
    test_exhaustion_total();
    test_packet_seq_exhaustion();
    test_disarmed_and_unarmed();
    test_lost_capability_reset();
    test_decoder_negatives();
    TEST_REPORT("line-crossing-live/wire");
}
