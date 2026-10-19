
#include "test_live.h"
#include "live_stub.h"
#include "ref_decoder.h"
#include "lc_lvn4.h"
#include "lc_compat.h"

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

static void test_real_bus_e2e_consistency(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 100u, 64u);

    live_det_t row[64];
    uint32_t i;
    for (i = 0; i < 16u; i++) row[i] = det_c(0.08f + 0.055f * (float)i, 0.42f);
    live_env_frame(e, 1000u, row, 16u);
    for (i = 0; i < 16u; i++) row[i] = det_c(0.08f + 0.055f * (float)i, 0.58f);
    live_env_frame(e, 1200u, row, 16u);
    live_env_idle(e, 500u);
    for (i = 0; i < 16u; i++) row[i] = det_c(0.08f + 0.055f * (float)i, 0.44f);
    live_env_frame(e, 1800u, row, 16u);

    CHECK_EQ_I(e->bus.total_in + e->bus.total_out, 32u);
    CHECK_EQ_I(e->prod.cumulative_total, 32u);
    CHECK_EQ_I(e->prod.through_seq, 32u);
    CHECK_EQ_I(e->prod.cumulative_gap, 0u);

    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n > 0u);
    uint32_t prev_seq = 0u;
    uint32_t prev_event_seq = 0u;
    uint32_t event_count = 0u;
    for (i = 0; i < n; i++) {
        CHECK_EQ_I(decode_pkt(e, i, &v), 0);
        CHECK_EQ_I(v.packet_seq, prev_seq + 1u);
        prev_seq = v.packet_seq;
        CHECK_EQ_I(v.config_generation, 1u);
        uint32_t j;
        for (j = 0; j < v.record_count; j++) {
            if (v.kind == 1u) {
                CHECK(v.events[j].seq > prev_event_seq);
                prev_event_seq = v.events[j].seq;
                event_count++;
            }
        }
    }
    CHECK_EQ_I(event_count, 32u);
    live_env_free(e);
}

static void test_unarmed_no_interference(void)
{
    live_env_t *a = live_env_new();
    live_env_arm(a, 200u, 64u);
    live_env_t *b = live_env_new();

    live_env_t *pair[2];
    pair[0] = a;
    pair[1] = b;
    int idx;
    for (idx = 0; idx < 2; idx++) {
        live_env_t *e = pair[idx];
        live_det_t d0 = det_c(0.5f, 0.40f);
        live_det_t d1 = det_c(0.5f, 0.60f);
        live_env_frame(e, 1000u, &d0, 1u);
        live_env_idle(e, 1000u);
        live_env_frame(e, 2100u, &d1, 1u);
        live_env_frame(e, 2200u, &d1, 1u);
        live_env_frame(e, 2300u, &d1, 1u);
        live_env_frame(e, 2400u, &d1, 1u);
        live_env_frame(e, 2500u, &d1, 1u);
        live_env_frame(e, 2600u, &d1, 1u);
        live_env_idle(e, 400000u);
    }

    CHECK_EQ_I(a->bus.total_in, b->bus.total_in);
    CHECK_EQ_I(a->bus.total_out, b->bus.total_out);
    CHECK_EQ_I(a->bus.report_seq, b->bus.report_seq);
    CHECK_EQ_I(a->bus.revision, b->bus.revision);
    CHECK_EQ_I(a->report_count, b->report_count);
    uint32_t i;
    for (i = 0; i < a->report_count && i < b->report_count; i++) {
        CHECK_EQ_I(a->report_len[i], b->report_len[i]);
        if (a->report_len[i] == b->report_len[i]) {
            CHECK(memcmp(a->reports[i], b->reports[i], a->report_len[i]) == 0);
        }
    }
    CHECK(a->report_count >= 1u);
    live_env_free(a);
    live_env_free(b);
}

static void test_frame_gap_events(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 300u, 8u);
    live_det_t d0 = det_c(0.5f, 0.40f);
    live_env_frame(e, 1000u, &d0, 1u);

    uint8_t buf[64];
    uint32_t len = live_gap_event(buf, sizeof(buf), 50u, 1100u, 0x1u, 2u);
    live_env_raw(e, buf, len);
    CHECK_EQ_I(e->bus.gaps_window, 1u);
    CHECK_EQ_I(e->bus.lost_window, 2u);

    len = live_gap_event(buf, sizeof(buf), 51u, 1200u, 0x2u, 0xFFFFFFFFu);
    live_env_raw(e, buf, len);
    CHECK_EQ_I(e->bus.lost_unknown_window, 1u);

    live_env_frame(e, 1300u, &d0, 1u);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= 2u);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.flags, 0x2u);
    CHECK_EQ_I(e->prod.st.gap_events, 2u);
    live_env_free(e);
}

static void test_alloc_failure_dropped_frame(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 400u, 8u);
    live_malloc_fail_after(1u);
    live_det_t d0 = det_c(0.5f, 0.40f);
    live_env_frame(e, 1000u, &d0, 1u);
    CHECK_EQ_I(e->bus.st.frames_unusable, 1u);
    CHECK_EQ_I(e->prod.loss_unknown_latch, 1u);
    live_malloc_fail_after(0u);
    live_env_frame(e, 1200u, &d0, 1u);
    live_env_frame(e, 1400u, &d0, 1u);
    live_env_frame(e, 1600u, &d0, 1u);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= 2u);
    CHECK_EQ_I(decode_pkt(e, n - 2u, &v), 0);
    CHECK_EQ_I(v.flags, 0x2u);
    CHECK_EQ_I(v.record_count, 0u);
    live_env_free(e);
}

static void test_idle_no_packets_window_regression(void)
{
    live_env_t *e = live_env_new();
    lc_bus_config_t cfg = e->bus.cfg;
    cfg.window_minutes = 1u;
    CHECK_EQ_I(lcbus_apply_config(&e->bus, &cfg), 0);
    live_env_arm(e, 500u, 8u);

    live_det_t d0 = det_c(0.5f, 0.40f);
    live_det_t d1 = det_c(0.5f, 0.60f);
    live_env_frame(e, 1000u, &d0, 1u);
    live_env_frame(e, 1200u, &d1, 1u);
    uint32_t n_before = live_rec_count(e->rec);

    uint32_t k;
    for (k = 0; k < 20u; k++) live_env_idle(e, 5000u);
    CHECK(live_rec_count(e->rec) >= n_before);
    CHECK_EQ_I(e->prod.cumulative_total, 1u);
    CHECK(e->bus.report_seq >= 1u);
    CHECK_EQ_I(e->bus.total_in + e->bus.total_out, 1u);
    CHECK(e->report_count >= 1u);
    live_env_free(e);
}

static void test_business_report_bytes_stable(void)
{
    live_env_t *a = live_env_new();
    lc_bus_config_t ca = a->bus.cfg;
    ca.window_minutes = 1u;
    (void)lcbus_apply_config(&a->bus, &ca);
    live_env_arm(a, 600u, 64u);

    live_env_t *b = live_env_new();
    lc_bus_config_t cb = b->bus.cfg;
    cb.window_minutes = 1u;
    (void)lcbus_apply_config(&b->bus, &cb);

    live_env_t *pair[2];
    pair[0] = a;
    pair[1] = b;
    int idx;
    for (idx = 0; idx < 2; idx++) {
        live_env_t *e = pair[idx];
        live_det_t dets[4];
        uint32_t i;
        for (i = 0; i < 4u; i++) dets[i] = det_c(0.3f + 0.1f * (float)i, 0.40f);
        live_env_frame(e, 1000u, dets, 4u);
        for (i = 0; i < 4u; i++) dets[i] = det_c(0.3f + 0.1f * (float)i, 0.60f);
        live_env_frame(e, 1200u, dets, 4u);
        live_env_idle(e, 70000u);
        live_env_idle(e, 70000u);
    }

    CHECK_EQ_I(a->report_count, b->report_count);
    CHECK(a->report_count >= 1u);
    uint32_t i;
    for (i = 0; i < a->report_count && i < b->report_count; i++) {
        CHECK_EQ_I(a->report_len[i], b->report_len[i]);
        if (a->report_len[i] == b->report_len[i]) {
            CHECK(memcmp(a->reports[i], b->reports[i], a->report_len[i]) == 0);
        }
    }
    CHECK_EQ_I(a->bus.report_seq, b->bus.report_seq);
    CHECK_EQ_I(a->bus.revision, b->bus.revision);
    live_env_free(a);
    live_env_free(b);
}

static void test_target_change_clear_view(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 700u, 8u);
    live_det_t d0 = det_c(0.5f, 0.40f);
    live_env_frame(e, 1000u, &d0, 1u);
    CHECK_EQ_I(e->bus.total_in + e->bus.total_out, 0u);

    lc_bus_config_t cfg = e->bus.cfg;
    lc_strlcpy(cfg.target_class_name, "other", sizeof(cfg.target_class_name));
    lcbus_cfg_txn_t txn;
    CHECK_EQ_I(lcbus_txn_prepare_config(&e->bus, &cfg, &txn), LCBUS_TXN_OK);
    CHECK_EQ_I(lcbus_txn_commit_config(&e->bus, &txn), LCBUS_TXN_OK);

    live_env_frame(e, 1200u, &d0, 1u);
    rd_view_t v;
    uint32_t n = live_rec_count(e->rec);
    CHECK(n >= 2u);
    CHECK_EQ_I(decode_pkt(e, n - 1u, &v), 0);
    CHECK_EQ_I(v.kind, 2u);
    CHECK_EQ_I(v.record_count, 0u);
    live_env_free(e);
}

static void test_malformed_frame_no_packets(void)
{
    live_env_t *e = live_env_new();
    live_env_arm(e, 800u, 8u);
    uint8_t bad[40];
    memset(bad, 0, sizeof(bad));
    bad[0] = 0x2c;
    bad[8] = 40u;
    bad[12] = 1u;
    live_env_raw(e, bad, 40u);
    CHECK_EQ_I(e->bus.st.malformed_events, 1u);
    CHECK_EQ_I(live_rec_count(e->rec), 0u);
    live_env_free(e);
}

int g_pass;
int g_fail;

int main(void)
{
    g_pass = 0;
    g_fail = 0;
    test_real_bus_e2e_consistency();
    test_unarmed_no_interference();
    test_frame_gap_events();
    test_alloc_failure_dropped_frame();
    test_idle_no_packets_window_regression();
    test_business_report_bytes_stable();
    test_target_change_clear_view();
    test_malformed_frame_no_packets();
    TEST_REPORT("line-crossing-live/bus");
}
