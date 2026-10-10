
#include "test_common.h"
#include "host_stub.h"
#include "lc_bus.h"
#include "lc_stateblob.h"

int g_pass = 0;
int g_fail = 0;

static lcstub_t *s;
static lc_app_api_v2_t tbl;
static lcbus_t bus;

static void setup(void)
{
    s = lcstub_new();
    lcstub_make_table(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    lcbus_restore(&bus);
    lcbus_rebind(&bus, 1);
}

static void teardown(void)
{
    lcstub_destroy(s);
    s = NULL;
}

static lc_bus_config_t cfg1(void)
{
    lc_bus_config_t c;
    lc_bus_config_defaults(&c);
    c.window_minutes = 1;
    return c;
}

static void run_crossing(int down, uint32_t x_center_permille, uint32_t mono0)
{
    static const float ys_down[4] = { 0.30f, 0.44f, 0.58f, 0.72f };
    static const float ys_up[4]   = { 0.72f, 0.58f, 0.44f, 0.30f };
    const float *ys = down ? ys_down : ys_up;
    float x = (float)x_center_permille / 1000.0f;
    for (int i = 0; i < 4; i++) {
        lcstub_det_t d = { x - 0.05f, ys[i] - 0.02f, 0.1f, 0.04f, 0.9f, 0 };
        lcstub_push_frame(s, 1, mono0 + (uint32_t)i * 100u, 7, 3, 0, 0, &d, 1);

        uint8_t buf[LC_APP_EVENT_BUF_CAP];
        uint32_t alen = 0;
        int slot = s->ev_head;
        memcpy(buf, s->events[slot], s->event_len[slot]);
        alen = s->event_len[slot];
        s->ev_head = (s->ev_head + 1) % LCSTUB_MAX_EVENTS;
        s->ev_count--;
        lcbus_on_event(&bus, buf, alen);
    }
}

static void pump_event(void)
{
    uint8_t buf[LC_APP_EVENT_BUF_CAP];
    uint32_t alen = 0;
    int slot = s->ev_head;
    memcpy(buf, s->events[slot], s->event_len[slot]);
    alen = s->event_len[slot];
    s->ev_head = (s->ev_head + 1) % LCSTUB_MAX_EVENTS;
    s->ev_count--;
    lcbus_on_event(&bus, buf, alen);
}

static const lcstub_report_t *close_window(uint32_t tick)
{
    uint32_t submits_before = lcstub_calls(s, LCSTUB_FN_REPORT_SUBMIT);
    lcstub_set_tick(s, tick);
    lcbus_on_idle(&bus);
    if (lcstub_calls(s, LCSTUB_FN_REPORT_SUBMIT) == submits_before) return NULL;
    return lcstub_report_by_seq(s, bus.report_seq);
}

static long json_num_region(const char *json, const char *region, const char *key)
{
    char pat[64];
    const char *p = json;
    if (region) {
        snprintf(pat, sizeof(pat), "\"%s\":", region);
        p = strstr(json, pat);
        if (!p) return -1;
        p += strlen(pat);
    }
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(p, pat);
    if (!p) return -1;
    p += strlen(pat);
    long v = 0;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
    return neg ? -v : v;
}

static void t01(void)
{
    printf("B01 window IN + counters + commit\n");
    setup();
    lc_bus_config_t c = cfg1();
    CHECK_EQ_I(lcbus_apply_config(&bus, &c), 0);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_RUNNING);
    CHECK_EQ_I(bus.binding.target_index, 0);
    CHECK_EQ_I(bus.revision, 1);

    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.window_in, 1);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(bus.window_out, 0);
    CHECK_EQ_I(bus.total_out, 0);
    CHECK_EQ_I(bus.st.frames_total, 4);
    CHECK_EQ_I(bus.state_dirty, 1);

    lcstub_set_tick(s, 6000);
    lcbus_flush(&bus, 0);
    CHECK_EQ_I(bus.st.state_commits_ok, 2);
    CHECK_EQ_I(s->state_present, 1);
    CHECK_EQ_I(s->state_revision, 2);

    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq;
    CHECK_EQ_I(lc_st_decode(s->state_blob, s->state_len, &scfg, &ti, &to, &wi, &wo, &seq),
               LC_ST_OK);
    CHECK_EQ_I(ti, 1);
    CHECK_EQ_I(wi, 1);
    CHECK_EQ_I(scfg.window_minutes, 1);
    teardown();
}

static void t02(void)
{
    printf("B02 window OUT\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(0, 500, 100);
    CHECK_EQ_I(bus.window_out, 1);
    CHECK_EQ_I(bus.total_out, 1);
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.total_in, 0);
    teardown();
}

static void t03(void)
{
    printf("B03 cumulative totals across windows, window reset\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    const lcstub_report_t *r = close_window(61000);
    CHECK(r != NULL);
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.total_in, 1);

    run_crossing(1, 200, 500);
    CHECK_EQ_I(bus.window_in, 1);
    CHECK_EQ_I(bus.total_in, 2);
    teardown();
}

static void t04(void)
{
    printf("B04 target class + confidence filtering\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);

    float xs[4] = { 0.30f, 0.44f, 0.58f, 0.72f };
    for (int i = 0; i < 4; i++) {
        lcstub_det_t dets[2] = {
            { 0.45f, xs[i] - 0.02f, 0.1f, 0.04f, 0.9f, 1 },
            { 0.70f, 0.20f - 0.02f, 0.1f, 0.04f, 0.9f, 0 },
        };
        lcstub_push_frame(s, 1, 100u + (uint32_t)i * 100u, 7, 3, 0, 0, dets, 2);
        pump_event();
    }
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.total_in, 0);

    for (int i = 0; i < 4; i++) {
        lcstub_det_t dets[2] = {
            { 0.45f, xs[i] - 0.02f, 0.1f, 0.04f, 0.9f, 0 },
            { 0.75f, xs[i] - 0.02f, 0.1f, 0.04f, 0.9f, 1 },
        };
        lcstub_push_frame(s, 1, 300u + (uint32_t)i * 100u, 7, 3, 0, 0, dets, 2);
        pump_event();
    }
    CHECK_EQ_I(bus.window_in, 1);
    CHECK_EQ_I(bus.total_in, 1);

    for (int i = 0; i < 4; i++) {
        lcstub_det_t d = { 0.30f - 0.05f, xs[i] - 0.02f, 0.1f, 0.04f, 0.1f, 0 };
        lcstub_push_frame(s, 1, 900u + (uint32_t)i * 100u, 7, 3, 0, 0, &d, 1);
        pump_event();
    }
    CHECK_EQ_I(bus.window_in, 1);
    teardown();
}

static void t05(void)
{
    printf("B05 counter name edit does NOT reset counters\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.total_in, 1);

    lc_bus_config_t edited = c;
    snprintf(edited.counter_name, sizeof(edited.counter_name), "counter-B");
    CHECK_EQ_I(lcbus_apply_config(&bus, &edited), 0);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(bus.window_in, 1);
    CHECK(strcmp(bus.cfg.counter_name, "counter-B") == 0);

    const lcstub_report_t *r = close_window(61000);
    CHECK(r != NULL);
    CHECK(strstr((const char *)r->bytes, "\"counter_name\":\"counter-B\"") != NULL);
    CHECK_EQ_I(json_num_region((const char *)r->bytes, "total", "in"), 1);
    teardown();
}

static void t06(void)
{
    printf("B06 target switch resets counters and rebinds\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.total_in, 1);

    lc_bus_config_t switched = c;
    snprintf(switched.target_class_name, sizeof(switched.target_class_name), "car");
    CHECK_EQ_I(lcbus_apply_config(&bus, &switched), 0);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.binding.target_index, 1);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_RUNNING);

    float xs[4] = { 0.30f, 0.44f, 0.58f, 0.72f };
    for (int i = 0; i < 4; i++) {
        lcstub_det_t dets[2] = {
            { 0.45f, xs[i] - 0.02f, 0.1f, 0.04f, 0.9f, 0 },
            { 0.75f, xs[i] - 0.02f, 0.1f, 0.04f, 0.9f, 1 },
        };
        lcstub_push_frame(s, 1, 700u + (uint32_t)i * 100u, 7, 3, 0, 0, dets, 2);
        pump_event();
    }
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(bus.window_in, 1);
    teardown();
}

static void t07(void)
{
    printf("B07 manual reset zeroes and persists\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    uint32_t seq_before = bus.report_seq;
    lcbus_reset(&bus);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK_EQ_I(bus.total_out, 0);
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.report_seq, seq_before);
    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq;
    CHECK_EQ_I(lc_st_decode(s->state_blob, s->state_len, &scfg, &ti, &to, &wi, &wo, &seq),
               LC_ST_OK);
    CHECK_EQ_I(ti, 0);
    teardown();
}

static void t08(void)
{
    printf("B08 restart recovery: totals/config/report_seq/window carried\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    bus.report_seq = 5;
    lcstub_set_tick(s, 6000);
    lcbus_flush(&bus, 0);

    lcbus_t bus2;
    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &tbl;
    lcbus_init(&bus2, &ops);
    lcbus_restore(&bus2);
    lcbus_rebind(&bus2, 1);
    CHECK_EQ_I(bus2.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(bus2.total_in, 1);
    CHECK_EQ_I(bus2.report_seq, 5);
    CHECK_EQ_I(bus2.cfg.window_minutes, 1);
    CHECK_EQ_I(bus2.window_carried, 1);
    CHECK_EQ_I(bus2.carried_in, 1);
    CHECK(strcmp(bus2.cfg.counter_name, c.counter_name) == 0);

    uint32_t submits_before = lcstub_calls(s, LCSTUB_FN_REPORT_SUBMIT);
    lcstub_set_tick(s, 67000);
    lcbus_on_idle(&bus2);
    CHECK(lcstub_calls(s, LCSTUB_FN_REPORT_SUBMIT) == submits_before + 1);
    const lcstub_report_t *r = lcstub_report_by_seq(s, bus2.report_seq);
    CHECK(r != NULL);
    if (r) {
        const char *json = (const char *)r->bytes;
        CHECK_EQ_I(json_num_region(json, "window", "in"), 1);
        CHECK_EQ_I(json_num_region(json, "window", "carried_in"), 1);
    }
    teardown();
}

static void t09(void)
{
    printf("B09 verified absence is NOT data loss\n");
    setup();
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_NONE);
    CHECK_EQ_I(bus.revision, 0);
    CHECK_EQ_I(bus.total_in, 0);
    teardown();
}

static void t10(void)
{
    printf("B10 storage unknown at boot -> degraded, then recovery\n");
    setup();
    lcstub_state_read_fault(s, LC_RET_STORAGE_UNKNOWN, 1);
    lcbus_restore(&bus);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_DEGRADED);
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(bus.st.state_commits_ok >= 1, 1);
    teardown();
}

static void t11(void)
{
    printf("B11 single revision conflict is recovered\n");
    setup();
    lcstub_state_commit_fault(s, LC_RET_REVISION_CONFLICT, 1);
    lc_bus_config_t c = cfg1();
    CHECK_EQ_I(lcbus_apply_config(&bus, &c), 0);

    CHECK_EQ_I(bus.st.state_conflicts, 1);
    CHECK_EQ_I(bus.st.state_commits_ok, 1);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    teardown();
}

static void t12(void)
{
    printf("B12 persistent conflict -> CONFLICT state, counting continues\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    lcstub_state_commit_fault(s, LC_RET_REVISION_CONFLICT, 2);
    run_crossing(1, 500, 100);
    lcstub_set_tick(s, 20000);
    lcbus_flush(&bus, 0);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_CONFLICT);
    CHECK_EQ_I(bus.st.state_conflicts, 1);
    uint32_t frozen = lcstub_calls(s, LCSTUB_FN_STATE_COMMIT);
    lcbus_flush(&bus, 0);
    CHECK_EQ_I(lcstub_calls(s, LCSTUB_FN_STATE_COMMIT), frozen);

    lcbus_flush(&bus, 1);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(bus.st.state_commits_ok, 2);

    CHECK_EQ_I(bus.total_in, 1);
    teardown();
}

static void t13(void)
{
    printf("B13 corrupt stored blob -> visible CORRUPT, then replaced\n");
    s = lcstub_new();
    lcstub_make_table(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    uint8_t junk[152];
    memset(junk, 0xAB, sizeof(junk));
    lcstub_set_state(s, junk, sizeof(junk), 4);
    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    lcbus_restore(&bus);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_CORRUPT);
    CHECK_EQ_I(bus.total_in, 0);
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    lcstub_destroy(s);
}

static void t14(void)
{
    printf("B14 model unsupported -> unusable frames, then recovery\n");
    setup();
    lcstub_set_model(s, 0, 7, 3, 2, "od-demo", "1.2");
    lcbus_rebind(&bus, 1);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_UNSUPPORTED_MODEL);
    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK_EQ_I(bus.st.frames_unusable, 4);

    lcstub_set_model(s, 1, 8, 3, 2, "od-demo", "1.2");
    lcstub_set_tick(s, 2000);
    run_crossing(1, 500, 1000);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_RUNNING);
    CHECK_EQ_I(bus.total_in, 1);
    teardown();
}

static void t15(void)
{
    printf("B15 wrong result_type is unsupported; class removal invalidates target\n");
    setup();
    s->meta_result_type_override = "seg";
    lcbus_rebind(&bus, 1);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_UNSUPPORTED_MODEL);
    s->meta_result_type_override = NULL;
    lcstub_set_tick(s, 2000);
    lcbus_rebind(&bus, 0);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_RUNNING);

    lcstub_set_class(s, 0, "vehicle");
    lcstub_set_tick(s, 4000);
    lcbus_rebind(&bus, 1);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_RUNNING);

    lcstub_set_model(s, 1, 7, 5, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "vehicle");
    lcstub_set_class(s, 1, "car");
    lcstub_set_tick(s, 6000);
    lcbus_rebind(&bus, 1);
    CHECK_EQ_I(bus.model_state, LCBUS_MSTATE_TARGET_CLASS_INVALID);
    teardown();
}

static void t16(void)
{
    printf("B16 GAP/lost-frame accounting is visible in the report\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);

    lcstub_push_kind(s, LC_EVT_KIND_GAP, 1, 50, 7, 3, 0, 3);
    pump_event();
    CHECK_EQ_I(bus.gaps_window, 1);
    CHECK_EQ_I(bus.lost_window, 3);

    lcstub_det_t d = { 0.45f, 0.28f, 0.1f, 0.04f, 0.9f, 0 };
    lcstub_push_frame(s, 2, 100, 7, 3, LC_EVT_FLAG_LOST_KNOWN, 2, &d, 1);
    pump_event();
    CHECK_EQ_I(bus.gaps_window, 2);
    CHECK_EQ_I(bus.lost_window, 5);

    lcstub_push_kind(s, LC_EVT_KIND_GAP, 3, 150, 7, 3, LC_EVT_FLAG_LOST_UNKNOWN,
                     LC_EVT_LOST_UNKNOWN_MARK);
    pump_event();
    CHECK_EQ_I(bus.lost_unknown_window, 1);
    CHECK_EQ_I(bus.gaps_window, 3);

    const lcstub_report_t *r = close_window(61000);
    CHECK(r != NULL);
    const char *json = (const char *)r->bytes;
    CHECK(strstr(json, "\"complete\":false") != NULL);
    CHECK_EQ_I(json_num_region(json, "data_quality", "gaps"), 3);
    CHECK_EQ_I(json_num_region(json, "data_quality", "lost_frames"), 5);
    CHECK(strstr(json, "\"lost_unknown\":true") != NULL);
    teardown();
}

static void t17(void)
{
    printf("B17 malformed events rejected (wire negative family)\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    uint8_t raw[128];

    lcstub_push_kind(s, 9, 1, 10, 7, 3, 0, 0);

    lcstub_push_kind(s, LC_EVT_KIND_FRAME, 1, 10, 7, 3, 0x20, 0);

    lcstub_push_kind(s, LC_EVT_KIND_FRAME, 1, 10, 7, 3, LC_EVT_FLAG_LOST_UNKNOWN, 3);

    {
        uint8_t b[LC_EVT_HDR_SIZE];
        memset(b, 0, sizeof(b));
        lcstub_wr32(b + 0, LC_EVT_HDR_SIZE);
        lcstub_wr32(b + 4, LC_EVT_KIND_GAP);
        lcstub_wr32(b + 28, 1);
        lcstub_push_raw(s, b, sizeof(b));
    }

    {
        uint8_t b[LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE];
        memset(b, 0, sizeof(b));
        lcstub_wr32(b + 0, LC_EVT_HDR_SIZE);
        lcstub_wr32(b + 4, LC_EVT_KIND_FRAME);
        lcstub_wr32(b + 28, 1);
        lcstub_push_raw(s, b, sizeof(b));
    }

    {
        memset(raw, 0, 40);
        lcstub_wr32(raw + 0, 40);
        lcstub_wr32(raw + 4, LC_EVT_KIND_FRAME);
        lcstub_wr32(raw + 36, 7);
        lcstub_push_raw(s, raw, 40);
    }

    {
        memset(raw, 0, LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE);
        lcstub_wr32(raw + 0, LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE);
        lcstub_wr32(raw + 4, LC_EVT_KIND_FRAME);
        lcstub_wr32(raw + 28, 1);
        lcstub_wr32(raw + 40, 0x7F800000u);
        lcstub_push_raw(s, raw, LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE);
    }

    {
        memset(raw, 0, LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE);
        lcstub_wr32(raw + 0, LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE);
        lcstub_wr32(raw + 4, LC_EVT_KIND_FRAME);
        lcstub_wr32(raw + 28, 1);
        lcstub_wr32(raw + 40, 0x3F800000u);
        lcstub_wr32(raw + 60, 99);
        lcstub_push_raw(s, raw, LC_EVT_HDR_SIZE + LC_EVT_REC_SIZE);
    }

    lcstub_push_raw(s, raw, 12);

    while (s->ev_count) pump_event();
    CHECK_EQ_I(bus.st.malformed_events, 9);
    CHECK_EQ_I(bus.st.frames_total, 0);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK(bus.gaps_window >= 9);
    teardown();
}

static void t18(void)
{
    printf("B18 NO_EVENT vs empty FRAME are distinct\n");
    setup();
    lcbus_on_idle(&bus);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(bus.st.no_event_polls, 2);
    CHECK_EQ_I(bus.st.frames_total, 0);

    lcstub_push_frame(s, 1, 100, 7, 3, 0, 0, NULL, 0);
    pump_event();
    CHECK_EQ_I(bus.st.frames_total, 1);
    CHECK_EQ_I(bus.st.frames_empty, 1);
    CHECK_EQ_I(bus.st.frames_unusable, 0);
    teardown();
}

static void t19(void)
{
    printf("B19 report quota drop is visible, identity still advances\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    lcstub_fault(s, LCSTUB_FN_REPORT_SUBMIT, LC_RET_QUOTA_EXCEEDED, 1);
    const lcstub_report_t *r = close_window(61000);
    CHECK(r == NULL);
    CHECK_EQ_I(bus.st.reports_dropped, 1);
    CHECK_EQ_I(bus.st.reports_submitted, 0);
    CHECK_EQ_I(bus.report_seq, 1);
    CHECK_EQ_I(bus.window_in, 0);

    run_crossing(1, 200, 500);
    r = close_window(121000);
    CHECK(r != NULL);
    CHECK_EQ_I(bus.st.reports_submitted, 1);
    CHECK_EQ_I(bus.report_seq, 2);
    teardown();
}

static void t20(void)
{
    printf("B20 accepted vs delivered are distinct; per-channel states\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    const lcstub_report_t *r = close_window(61000);
    CHECK(r != NULL);
    CHECK_EQ_I(bus.st.reports_submitted, 1);
    CHECK_EQ_I(bus.st.reports_delivered_mqtt, 0);

    lcstub_set_report_state(s, 1, LC_RSTATE_TRANSPORT_SUCCEEDED, LC_RSTATE_PENDING);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(bus.st.reports_delivered_mqtt, 1);
    CHECK_EQ_I(bus.st.reports_delivered_webhook, 0);

    lcstub_set_report_state(s, 1, LC_RSTATE_TRANSPORT_SUCCEEDED, LC_RSTATE_NOT_CONFIGURED);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(bus.st.reports_delivered_webhook, 0);

    run_crossing(1, 200, 500);
    lcstub_set_report_channels(s, LC_RSTATE_PENDING, LC_RSTATE_NOT_CONFIGURED);
    r = close_window(121000);
    CHECK(r != NULL);
    lcstub_set_report_state(s, 2, LC_RSTATE_TRANSPORT_FAILED, LC_RSTATE_NOT_CONFIGURED);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(bus.st.reports_failed_transport, 1);
    teardown();
}

static void t21(void)
{
    printf("B21 MODEL_CHANGED rebinds, clears transient, keeps totals\n");
    setup();
    lc_bus_config_t c = cfg1();
    lcbus_apply_config(&bus, &c);
    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.total_in, 1);

    lcstub_set_model(s, 1, 8, 4, 2, "od-demo", "1.2");
    lcstub_push_kind(s, LC_EVT_KIND_MODEL_CHANGED, 9, 500, 8, 4, 0, 0);
    pump_event();
    CHECK_EQ_I(bus.binding.model_generation, 8);
    CHECK_EQ_I(bus.binding.class_generation, 4);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK(bus.tracker == NULL);

    run_crossing(1, 500, 600);
    CHECK_EQ_I(bus.total_in, 2);
    teardown();
}

int main(void)
{
    t01(); t02(); t03(); t04(); t05(); t06(); t07(); t08();
    t09(); t10(); t11(); t12(); t13(); t14(); t15(); t16();
    t17(); t18(); t19(); t20(); t21();
    TEST_REPORT("test_business");
}
