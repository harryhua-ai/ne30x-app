
#include "test_common.h"
#include "host_stub.h"
#include "lc_bus.h"
#include "lc_ctrl.h"
#include "lc_app_entry_v3.h"
#include "lc_stateblob.h"
#include "lc_cfgcodec.h"
#include "lc_compat.h"

int g_pass = 0;
int g_fail = 0;

static lcstub_t *s;
static lc_app_api_v3_t tbl;
static lcbus_t bus;
static lc_ctrl_t ctrl;

static void base_init(void)
{
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    lcbus_rebind(&bus, 1);
}

static void setup(void)
{
    base_init();
    lcbus_flush(&bus, 1);
    lc_ctrl_poll(&ctrl);
}

static void teardown(void)
{
    lcstub_destroy(s);
    s = NULL;
}

static const char *last_snapshot(uint32_t *plen)
{
    uint32_t n = lcstub_snapshot_count(s);
    if (n == 0) return NULL;
    const uint8_t *snap = lcstub_snapshot(s, n - 1, plen);
    if (!snap) return NULL;
    return (const char *)(snap + LC_CTRL_HEADER_SIZE);
}

static int json_has(const char *needle)
{
    uint32_t plen = 0;
    const char *json = last_snapshot(&plen);
    if (!json) return 0;
    return strstr(json, needle) != NULL;
}

static void publish_now(void) { lc_ctrl_poll(&ctrl); }

static void s01_projection_complete(void)
{
    printf("S01 snapshot projection carries full editable config and trust facts\n");
    setup();
    uint32_t plen = 0;
    const char *json = last_snapshot(&plen);
    CHECK(json != NULL);
    if (!json) { teardown(); return; }
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)json,
                                          plen - LC_CTRL_HEADER_SIZE), 1);

    CHECK(json_has("\"schema\":\"line-crossing/1\""));
    CHECK(json_has("\"config_generation\":1"));
    CHECK(json_has("\"app_state\":\"running\""));
    CHECK(json_has("\"storage\":{\"state\":\"ok\",\"withheld\":false}"));
    CHECK(json_has("\"model\":{\"valid\":true"));
    CHECK(json_has("\"target_class\":\"person\""));
    CHECK(json_has("\"counter_name\":"));
    CHECK(json_has("\"target_class_name\":\"person\""));
    CHECK(json_has("\"line\":{\"x1_permille\":200,\"y1_permille\":500,\"x2_permille\":800,\"y2_permille\":500}"));
    CHECK(json_has("\"outside\":{\"x_permille\":500,\"y_permille\":200}"));
    CHECK(json_has("\"conf_threshold_permille\":250"));
    CHECK(json_has("\"max_dist_permille\":250"));
    CHECK(json_has("\"track_history_k\":8"));
    CHECK(json_has("\"max_miss\":5"));
    CHECK(json_has("\"k_confirm\":5"));
    CHECK(json_has("\"window_minutes\":5"));
    CHECK(json_has("\"tracks_report_enable\":true"));
    CHECK(json_has("\"heat_grid_enable\":false"));
    CHECK(json_has("\"report_seq\":0"));
    CHECK(json_has("\"cumulative\":{\"in\":0,\"out\":0}"));
    CHECK(json_has("\"counters\":{\"in\":0,\"out\":0}"));
    CHECK(json_has("\"gap\":{\"gaps\":0,\"lost\":0,\"lost_unknown\":false,\"unusable\":0}"));

    uint32_t n = lcstub_snapshot_count(s);
    const uint8_t *snap = lcstub_snapshot(s, n - 1, &plen);
    CHECK(snap != NULL);
    if (snap) {
        CHECK_EQ_I(lc_rd_u32(snap + LC_CTRL_OFF_PROTO_MAGIC), LC_CTRL_PROTO_MAGIC);
        CHECK_EQ_I(snap[LC_CTRL_OFF_MSG_TYPE], LC_CTRL_TYPE_SNAPSHOT);
        CHECK_EQ_I(lc_rd_u32(snap + LC_CTRL_OFF_TOTAL_LEN), plen);
        CHECK_EQ_I(lc_rd_u32(snap + LC_CTRL_OFF_SESSION_GENERATION), 0u);
        CHECK_EQ_I(lc_rd_u32(snap + LC_CTRL_OFF_REQUEST_ID), 0u);
        CHECK_EQ_I(lc_rd_u32(snap + LC_CTRL_OFF_CONFIG_GENERATION), 1u);
        CHECK_EQ_I(lc_rd_u32(snap + LC_CTRL_OFF_FLAGS), 0u);
    }
    teardown();
}

static void fill_worst_case_state(void)
{
    lc_bus_config_t *c = &bus.cfg;
    for (int i = 0; i < 21; i++) {
        c->counter_name[i * 3 + 0] = (char)0xe5;
        c->counter_name[i * 3 + 1] = (char)0xae;
        c->counter_name[i * 3 + 2] = (char)0xb8;
    }
    c->counter_name[63] = '\0';
    lc_strlcpy(c->target_class_name, "abcdefghijklmnopqrstuvwxyz01234",
               sizeof(c->target_class_name));
    c->line_x1_permille = 1000u;
    c->line_y1_permille = 1000u;
    c->line_x2_permille = 1000u;
    c->line_y2_permille = 1000u;
    c->outside_x_permille = 1000u;
    c->outside_y_permille = 1000u;
    c->conf_threshold_permille = 1000u;
    c->max_dist_permille = 1000u;
    c->track_history_k = 16u;
    c->max_miss = 255u;
    c->k_confirm = 255u;
    c->window_minutes = 1440u;
    c->tracks_report_enable = 1u;
    c->heat_grid_enable = 1u;
    bus.total_in = 0xFFFFFFFFu;
    bus.total_out = 0xFFFFFFFFu;
    bus.window_in = 0xFFFFFFFFu;
    bus.window_out = 0xFFFFFFFFu;
    bus.report_seq = 0xFFFFFFFFu;
    bus.revision = 0xFFFFFFFFu;
    bus.gaps_window = 0xFFFFFFFFu;
    bus.lost_window = 0xFFFFFFFFu;
    bus.lost_unknown_window = 1;
    bus.unusable_window = 0xFFFFFFFFu;
    bus.config_generation = 0xFFFFFFFEu;
    lc_strlcpy(bus.binding.target_name, "abcdefghijklmnopqrstuvwxyz01234",
               sizeof(bus.binding.target_name));
    bus.binding.bound = 1;
    bus.binding.model_generation = 0xFFFFFFFFu;
    bus.binding.class_generation = 0xFFFFFFFFu;
    bus.model_state = LCBUS_MSTATE_RUNNING;
}

static void s02_worst_case_occupancy(void)
{
    printf("S02 worst-case legal snapshot fits declared 1024B quota\n");
    setup();
    fill_worst_case_state();
    uint32_t before = lcstub_snapshot_count(s);
    lc_ctrl_snapshot_force(&ctrl);
    publish_now();
    CHECK_EQ_I(lcstub_snapshot_count(s), before + 1);
    uint32_t plen = 0;
    const uint8_t *snap = lcstub_snapshot(s, lcstub_snapshot_count(s) - 1, &plen);
    CHECK(snap != NULL);
    if (snap) {
        CHECK_EQ_I(plen, LC_CTRL_HEADER_SIZE + (uint32_t)strlen((const char *)(snap + LC_CTRL_HEADER_SIZE)));
        CHECK(plen <= LC_SNAPSHOT_BUF_CAP);
        printf("SNAPSHOT_OCCUPANCY total=%u payload=%u declared_max=%u\n",
               plen, plen - LC_CTRL_HEADER_SIZE, LC_SNAPSHOT_BUF_CAP);
        CHECK_EQ_I(lcstub_snapshot_valid_json(snap + LC_CTRL_HEADER_SIZE,
                                              plen - LC_CTRL_HEADER_SIZE), 1);
    }
    teardown();
}

static void s03_degraded_not_trusted(void)
{
    printf("S03 degraded storage projected as untrusted, writes withheld\n");
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    lcstub_state_read_fault(s, LC_RET_STORAGE_UNKNOWN, 1);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    lcbus_rebind(&bus, 1);
    publish_now();
    CHECK(json_has("\"app_state\":\"restricted\""));
    CHECK(json_has("\"state\":\"degraded\""));
    CHECK(json_has("\"withheld\":true"));
    teardown();
}

static void s04_unbound_not_running(void)
{
    printf("S04 unbound model projected as unbound, model invalid\n");
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 0, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    lcbus_rebind(&bus, 1);
    publish_now();
    CHECK(json_has("\"app_state\":\"unbound\""));
    CHECK(json_has("\"model\":{\"valid\":false"));
    teardown();
}

static void s05_freshness_interval(void)
{
    printf("S05 snapshot refreshes at least every 5 seconds\n");
    setup();
    uint32_t n0 = lcstub_snapshot_count(s);
    s->tick_now += 4999u;
    publish_now();
    CHECK_EQ_I(lcstub_snapshot_count(s), n0);
    s->tick_now += 1u;
    publish_now();
    CHECK_EQ_I(lcstub_snapshot_count(s), n0 + 1);
    teardown();
}

static void s06_quota_whole_reject(void)
{
    printf("S06 host snapshot quota exceeded -> whole snapshot withheld, no truncation\n");
    setup();
    lcstub_set_control_capacity(s, LC_CTRL_CONTROL_MAX_DECLARED, 64u);
    uint32_t before = ctrl.st.snapshots_rejected;
    s->tick_now += 6000u;
    publish_now();
    CHECK_EQ_I(ctrl.st.snapshots_rejected, before + 1u);
    CHECK_EQ_I(bus.session_fatal, 0);
    teardown();
}

static void s07_escaped_name_stays_valid(void)
{
    printf("S07 quote-bearing restored name stays valid JSON via escaping\n");
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    lc_bus_config_t c;
    lc_bus_config_defaults(&c);
    lc_strlcpy(c.counter_name, "a\"b\\c", sizeof(c.counter_name));
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t n = lc_st_encode_gen(blob, sizeof(blob), &c, 1u, 2u, 0u, 0u, 5u, 9u);
    CHECK_EQ_I(n, LC_ST_BLOB_SIZE_GEN);
    lcstub_set_state(s, blob, n, 6);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(bus.config_generation, 9u);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    lcbus_rebind(&bus, 1);
    publish_now();
    CHECK(json_has("\"counter_name\":\"a\\\"b\\\\c\""));
    uint32_t plen = 0;
    const char *json = last_snapshot(&plen);
    CHECK(json != NULL);
    if (json) {
        CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)json,
                                              plen - LC_CTRL_HEADER_SIZE), 1);
    }
    teardown();
}

int main(void)
{
    s01_projection_complete();
    s02_worst_case_occupancy();
    s03_degraded_not_trusted();
    s04_unbound_not_running();
    s05_freshness_interval();
    s06_quota_whole_reject();
    s07_escaped_name_stays_valid();
    TEST_REPORT("snapshot");
}
