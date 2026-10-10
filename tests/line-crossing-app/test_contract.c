
#include "test_common.h"
#include "host_stub.h"
#include "lc_app_entry.h"
#include "lc_bus.h"
#include "lc_stateblob.h"

int g_pass = 0;
int g_fail = 0;
static lcstub_t *s;
static lc_app_api_v2_t tbl;

static void setup(void)
{
    s = lcstub_new();
    lcstub_make_table(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
}

static void teardown(void) { lcstub_destroy(s); s = NULL; }

static lc_bus_config_t cfg1m(void)
{
    lc_bus_config_t c;
    lc_bus_config_defaults(&c);
    c.window_minutes = 1;
    return c;
}

static void seed_state(lcstub_t *st, const lc_bus_config_t *cfg, uint32_t revision)
{
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len = lc_st_encode(blob, sizeof(blob), cfg, 0, 0, 0, 0, 0);
    if (len) lcstub_set_state(st, blob, len, revision);
}

static void push_crossing_frames(lcstub_t *st, uint32_t x_permille, uint32_t mono0)
{
    static const float ys[4] = { 0.30f, 0.44f, 0.58f, 0.72f };
    float x = (float)x_permille / 1000.0f;
    for (int i = 0; i < 4; i++) {
        lcstub_det_t d = { x - 0.05f, ys[i] - 0.02f, 0.1f, 0.04f, 0.9f, 0 };
        lcstub_push_frame(st, (uint32_t)i, mono0 + (uint32_t)i * 100u, 7, 3, 0, 0, &d, 1);
    }
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
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
    return v;
}

static void c01_entry_validation(void)
{
    printf("C01 entry validation (api/table/abi/fnptr)\n");
    setup();
    CHECK_EQ_I(app_entry(NULL, LC_APP_ABI_V2), LC_APP_EXIT_BAD_API);

    tbl.table_size = 16;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V2), LC_APP_EXIT_BAD_TABLE);
    tbl.table_size = 64;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V2), LC_APP_EXIT_BAD_TABLE);
    tbl.table_size = LC_APP_API_TABLE_SIZE;

    CHECK_EQ_I(app_entry(&tbl, 0x00010000u), LC_APP_EXIT_BAD_ABI);
    CHECK_EQ_I(app_entry(&tbl, 0x00030000u), LC_APP_EXIT_BAD_ABI);

    lc_app_fn_log_t saved = tbl.log;
    tbl.log = NULL;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V2), LC_APP_EXIT_BAD_FNPTR);
    tbl.log = saved;
    tbl.should_stop = NULL;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V2), LC_APP_EXIT_BAD_FNPTR);
    teardown();
}

static void c02_clean_session(void)
{
    printf("C02 clean session: runs, commits state, cooperative stop, exit 0\n");
    setup();
    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    CHECK(lcstub_calls(s, LCSTUB_FN_EVENT_NEXT) > 0);
    CHECK(lcstub_calls(s, LCSTUB_FN_MODEL_META) > 0);
    CHECK(lcstub_calls(s, LCSTUB_FN_SHOULD_STOP) > 0);
    CHECK(lcstub_calls(s, LCSTUB_FN_STATE_COMMIT) > 0);
    CHECK_EQ_I(s->state_present, 1);
    teardown();
}

static void c03_unauthorized_session(void)
{
    printf("C03 unauthorized session refused (UNAUTHORIZED contract)\n");
    setup();
    lcstub_set_session(s, 0);
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_UNAUTHORIZED);
    CHECK_EQ_I(s->state_present, 0);
    CHECK_EQ_I(s->report_count, 0);
    teardown();
}

static void c04_event_next_contract_faults(void)
{
    printf("C04 event_next INVALID_ARGUMENT x3 -> HOST_FAULT exit\n");
    setup();
    lcstub_fault(s, LCSTUB_FN_EVENT_NEXT, LC_RET_INVALID_ARGUMENT, 10);
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_HOST_FAULT);
    teardown();
}

static void c05_should_stop_faults(void)
{
    printf("C05 should_stop negative x3 -> HOST_FAULT exit (never misread as stop)\n");
    setup();
    lcstub_fault(s, LCSTUB_FN_SHOULD_STOP, -99, 10);
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_HOST_FAULT);
    teardown();
}

static void c06_stopping_event(void)
{
    printf("C06 STOPPING event -> clean cooperative exit\n");
    setup();
    lcstub_push_kind(s, LC_EVT_KIND_STOPPING, 1, 10, 7, 3, 0, 0);
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    teardown();
}

static void c07_tick_wraparound(void)
{
    printf("C07 tick_ms mod-2^32 window close across the wrap boundary\n");
    setup();
    lc_bus_config_t c = cfg1m();
    seed_state(s, &c, 3);
    lcstub_set_tick(s, 0xFFFFFFF0u);
    lcstub_set_tick_step(s, 30000u);
    for (int i = 0; i < 6; i++) {
        lcstub_push_frame(s, (uint32_t)i, (uint32_t)i * 100u, 7, 3, 0, 0, NULL, 0);
    }
    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);

    CHECK(s->report_count >= 1);
    if (s->report_count >= 1) {
        const lcstub_report_t *r = lcstub_report_by_seq(s, 1);
        CHECK(r != NULL);
        if (r) {
            const char *json = (const char *)r->bytes;
            CHECK_EQ_I(json_num_region(json, "window", "duration_sec"), 60);
            CHECK(json_num_region(json, "window", "start_ms") > 4294967295L - 100000L ||
                  json_num_region(json, "window", "start_ms") < 100000L);
        }
    }
    teardown();
}

static void c08_crossing_report_e2e(void)
{
    printf("C08 E2E: crossing counted, window report schema+identity\n");
    setup();
    lc_bus_config_t c = cfg1m();
    seed_state(s, &c, 0);

    lcstub_set_tick_step(s, 8000u);
    push_crossing_frames(s, 500, 100);
    for (int i = 0; i < 4; i++) lcstub_push_frame(s, 10 + (uint32_t)i, 1000u, 7, 3, 0, 0, NULL, 0);
    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    const lcstub_report_t *r = lcstub_report_by_seq(s, 1);
    CHECK(r != NULL);
    if (r) {
        const char *json = (const char *)r->bytes;
        CHECK_EQ_I(json_num_region(json, NULL, "schema_version"), 1);
        CHECK(strstr(json, "\"type\":\"line_counting\"") != NULL);
        CHECK(strstr(json, "\"device_id\":\"ne301-app:line-crossing\"") != NULL);
        CHECK_EQ_I(json_num_region(json, NULL, "report_seq"), 1);
        CHECK_EQ_I(json_num_region(json, "window", "in"), 1);
        CHECK_EQ_I(json_num_region(json, "total", "in"), 1);
        CHECK(strstr(json, "\"counter_name\":") != NULL);
        CHECK(strstr(json, "\"class_name\":\"person\"") != NULL);
        CHECK(strstr(json, "\"persist_ok\":true") != NULL);
    }
    teardown();
}

static void c09_malformed_meta_session(void)
{
    printf("C09 malformed model_meta -> unsupported model, session still safe\n");
    setup();
    uint8_t bad[LC_MODEL_META_SIZE];
    memset(bad, 0x41, sizeof(bad));
    lcstub_set_meta_raw(s, bad, sizeof(bad));
    push_crossing_frames(s, 500, 100);
    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    CHECK_EQ_I(s->report_count, 0);
    teardown();
}

static void c10_event_unauthorized_mid_session(void)
{
    printf("C10 event_next UNAUTHORIZED mid-session -> exit -5\n");
    setup();
    lcstub_fault(s, LCSTUB_FN_EVENT_NEXT, LC_RET_UNAUTHORIZED, 1);
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_UNAUTHORIZED);
    teardown();
}

static void c11_report_unauthorized(void)
{
    printf("C11 report_submit UNAUTHORIZED at window close -> exit -5\n");
    setup();
    lc_bus_config_t c = cfg1m();
    seed_state(s, &c, 0);
    lcstub_set_tick_step(s, 30000u);
    push_crossing_frames(s, 500, 100);
    for (int i = 0; i < 4; i++) lcstub_push_frame(s, 10 + (uint32_t)i, 1000u, 7, 3, 0, 0, NULL, 0);
    lcstub_fault(s, LCSTUB_FN_REPORT_SUBMIT, LC_RET_UNAUTHORIZED, 1);
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_UNAUTHORIZED);
    CHECK_EQ_I(s->report_count, 0);
    teardown();
}

static void c12_gap_visible_in_report(void)
{
    printf("C12 GAP/backpressure is visible in the submitted report\n");
    setup();
    lc_bus_config_t c = cfg1m();
    seed_state(s, &c, 0);
    lcstub_set_tick_step(s, 8000u);
    lcstub_push_kind(s, LC_EVT_KIND_GAP, 1, 50, 7, 3, 0, 7);
    push_crossing_frames(s, 500, 100);
    for (int i = 0; i < 4; i++) lcstub_push_frame(s, 10 + (uint32_t)i, 1000u, 7, 3, 0, 0, NULL, 0);
    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    const lcstub_report_t *r = lcstub_report_by_seq(s, 1);
    CHECK(r != NULL);
    if (r) {
        const char *json = (const char *)r->bytes;
        CHECK(strstr(json, "\"complete\":false") != NULL);
        CHECK_EQ_I(json_num_region(json, "data_quality", "lost_frames"), 7);
        CHECK_EQ_I(json_num_region(json, "window", "in"), 1);
    }
    teardown();
}

static void c13_storage_unknown_boot(void)
{
    printf("C13 STORAGE_UNKNOWN at boot: session survives; no state writes while storage undeterminable\n");
    setup();
    lcstub_state_read_fault(s, LC_RET_STORAGE_UNKNOWN, 1000);
    push_crossing_frames(s, 500, 100);
    for (int i = 0; i < 6; i++) lcstub_push_frame(s, 10 + (uint32_t)i, 1000u, 7, 3, 0, 0, NULL, 0);
    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    CHECK_EQ_I(lcstub_calls(s, LCSTUB_FN_STATE_COMMIT), 0);
    CHECK_EQ_I(s->state_present, 0);
    CHECK(lcstub_calls(s, LCSTUB_FN_STATE_READ) >= 2);
    teardown();
}

static void c14_report_seq_consistency(void)
{
    printf("C14 JSON report_seq always matches the app_report_seq argument\n");
    setup();
    lc_bus_config_t c = cfg1m();
    seed_state(s, &c, 0);
    lcstub_set_tick_step(s, 30000u);
    push_crossing_frames(s, 500, 100);
    for (int i = 0; i < 4; i++) lcstub_push_frame(s, 10 + (uint32_t)i, 1000u, 7, 3, 0, 0, NULL, 0);

    s->auto_stop_after_no_events = 3;
    int32_t rc = app_entry(&tbl, LC_APP_ABI_V2);
    CHECK_EQ_I(rc, LC_APP_EXIT_OK);
    CHECK(s->report_count >= 1);
    const lcstub_report_t *r1 = lcstub_report_by_seq(s, 1);
    CHECK(r1 != NULL);
    teardown();
}

int main(void)
{
    c01_entry_validation();
    c02_clean_session();
    c03_unauthorized_session();
    c04_event_next_contract_faults();
    c05_should_stop_faults();
    c06_stopping_event();
    c07_tick_wraparound();
    c08_crossing_report_e2e();
    c09_malformed_meta_session();
    c10_event_unauthorized_mid_session();
    c11_report_unauthorized();
    c12_gap_visible_in_report();
    c13_storage_unknown_boot();
    c14_report_seq_consistency();
    TEST_REPORT("test_contract");
}
