
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

static void setup(void)
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
    lc_ctrl_poll(&ctrl);
}

static void teardown(void)
{
    lcstub_destroy(s);
    s = NULL;
}

static lc_bus_config_t cfg_def(void)
{
    lc_bus_config_t c;
    lc_bus_config_defaults(&c);
    return c;
}

static void seed_state_v2(const char *counter, uint32_t ti, uint32_t to,
                          uint32_t seq, uint32_t revision)
{
    lc_bus_config_t c = cfg_def();
    lc_strlcpy(c.counter_name, counter, sizeof(c.counter_name));
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t n = lc_st_encode(blob, sizeof(blob), &c, ti, to, 0, 0, seq);
    if (n) lcstub_set_state(s, blob, n, revision);
}

static void poll_ctrl(void) { lc_ctrl_poll(&ctrl); }

static int push_apply(const lc_bus_config_t *cand, uint32_t flags,
                      uint32_t session, uint32_t req, uint32_t expected_gen)
{
    uint8_t payload[LC_CFG_CAND_SIZE];
    uint32_t plen = lc_cfg_encode(payload, sizeof(payload), cand);
    if (plen != LC_CFG_CAND_SIZE) return -1;
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                                       session, req, expected_gen, flags,
                                       payload, plen);
    if (len == 0) return -1;
    lcstub_push_command(s, cmd, len);
    return 0;
}

static int push_reset(uint32_t flags, uint32_t session, uint32_t req,
                      uint32_t expected_gen)
{
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_COUNTERS_RESET,
                                       session, req, expected_gen, flags, NULL, 0u);
    if (len == 0) return -1;
    lcstub_push_command(s, cmd, len);
    return 0;
}

static int reply_status(int index, uint32_t *status, uint32_t *gen, uint32_t *rev,
                        uint32_t *session, uint32_t *req)
{
    const uint8_t *r = lcstub_reply(s, index);
    if (!r) return 0;
    uint32_t type = (uint32_t)r[LC_CTRL_OFF_MSG_TYPE] |
                    ((uint32_t)r[LC_CTRL_OFF_MSG_TYPE + 1u] << 8);
    if (type != LC_CTRL_TYPE_REPLY) return 0;
    if (status) *status = lc_rd_u32(r + LC_CTRL_OFF_FLAGS);
    if (gen) *gen = lc_rd_u32(r + LC_CTRL_OFF_CONFIG_GENERATION);
    if (rev) *rev = lc_rd_u32(r + LC_CTRL_OFF_STATE_REVISION);
    if (session) *session = lc_rd_u32(r + LC_CTRL_OFF_SESSION_GENERATION);
    if (req) *req = lc_rd_u32(r + LC_CTRL_OFF_REQUEST_ID);
    return 1;
}

static const char *last_snapshot_json(uint32_t *plen)
{
    uint32_t n = lcstub_snapshot_count(s);
    if (n == 0) return NULL;
    const uint8_t *snap = lcstub_snapshot(s, n - 1, plen);
    if (!snap) return NULL;
    return (const char *)(snap + LC_CTRL_HEADER_SIZE);
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

static void t_v01_stale_generation(void)
{
    printf("V01 stale expected_config_generation rejected, nothing changes\n");
    setup();
    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.total_in, 1);
    uint32_t rev0 = bus.revision;
    CHECK_EQ_I(push_apply(&bus.cfg, 0, 5, 42, bus.config_generation + 1u), 0);
    poll_ctrl();
    uint32_t st, gen, rev;
    CHECK_EQ_I(reply_status(0, &st, &gen, &rev, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_STALE_CONFIG);
    CHECK_EQ_I(gen, bus.config_generation);
    CHECK_EQ_I(rev, rev0);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(ctrl.st.rejected_stale_config, 1u);
    teardown();
}

static void t_v02_reset_unconfirmed(void)
{
    printf("V02 COUNTERS_RESET without destructive confirmation rejected\n");
    setup();
    run_crossing(1, 500, 100);
    CHECK_EQ_I(push_reset(0, 5, 43, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_UNCONFIRMED);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(ctrl.st.rejected_unconfirmed, 1u);
    teardown();
}

static void t_v03_target_change_unconfirmed(void)
{
    printf("V03 target class change without confirmation rejected\n");
    setup();
    run_crossing(1, 500, 100);
    lc_bus_config_t cand = cfg_def();
    lc_strlcpy(cand.target_class_name, "car", sizeof(cand.target_class_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 44, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_UNCONFIRMED);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(lc_strcmp(bus.cfg.target_class_name, "person"), 0);
    teardown();
}

static void t_v04_apply_rename_keeps_counts(void)
{
    printf("V04 counter_name-only apply preserves counts/report_seq, advances generation\n");
    setup();
    run_crossing(1, 500, 100);
    bus.report_seq = 9;
    lcbus_flush(&bus, 1);
    uint32_t rev0 = bus.revision;
    uint32_t seq0 = bus.report_seq;
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "new-name", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 45, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st, gen, rev;
    CHECK_EQ_I(reply_status(0, &st, &gen, &rev, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(gen, 2u);
    CHECK_EQ_I(rev, rev0 + 1u);
    CHECK_EQ_I(bus.config_generation, 2u);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(bus.report_seq, seq0);
    CHECK_EQ_I(lc_strcmp(bus.cfg.counter_name, "new-name"), 0);
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);
    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq, sgen;
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(ti, 1u);
    CHECK_EQ_I(seq, seq0);
    CHECK_EQ_I(sgen, 2u);
    CHECK_EQ_I(ctrl.st.applied, 1u);
    uint32_t slen = 0;
    const char *json = last_snapshot_json(&slen);
    CHECK(json != NULL);
    if (json) {
        CHECK(strstr(json, "\"config_generation\":2") != NULL);
        CHECK(strstr(json, "\"counter_name\":\"new-name\"") != NULL);
    }
    teardown();
}

static void t_v05_line_change_boundary(void)
{
    printf("V05 line change switches at event boundary, counts preserved\n");
    setup();
    run_crossing(1, 500, 100);
    CHECK_EQ_I(bus.total_in, 1);
    lc_bus_config_t cand = bus.cfg;
    cand.line_x1_permille = 300u;
    cand.line_x2_permille = 700u;
    CHECK_EQ_I(push_apply(&cand, 0, 5, 46, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st, gen;
    CHECK_EQ_I(reply_status(0, &st, &gen, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(bus.cfg.line_x1_permille, 300u);
    CHECK(bus.line != NULL);
    run_crossing(1, 500, 900);
    CHECK_EQ_I(bus.total_in, 2);
    CHECK_EQ_I(gen, 2u);
    teardown();
}

static void t_v06_target_change_confirmed_resets(void)
{
    printf("V06 confirmed target change resets counters, keeps report_seq, rebinds\n");
    setup();
    run_crossing(1, 500, 100);
    bus.report_seq = 4;
    lcbus_flush(&bus, 1);
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.target_class_name, "car", sizeof(cand.target_class_name));
    CHECK_EQ_I(push_apply(&cand, LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 47,
                          bus.config_generation), 0);
    poll_ctrl();
    uint32_t st, gen;
    CHECK_EQ_I(reply_status(0, &st, &gen, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(gen, 2u);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK_EQ_I(bus.total_out, 0);
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.report_seq, 4u);
    CHECK_EQ_I(bus.binding.bound, 1);
    CHECK_EQ_I(bus.binding.target_index, 1);
    CHECK_EQ_I(lc_strcmp(bus.cfg.target_class_name, "car"), 0);
    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq, sgen;
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(ti, 0u);
    CHECK_EQ_I(seq, 4u);
    CHECK_EQ_I(sgen, 2u);
    teardown();
}

static void t_v07_target_missing_invalid(void)
{
    printf("V07 target class not in loaded model rejected as invalid\n");
    setup();
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.target_class_name, "dog", sizeof(cand.target_class_name));
    CHECK_EQ_I(push_apply(&cand, LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 48,
                          bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_INVALID);
    CHECK_EQ_I(lc_strcmp(bus.cfg.target_class_name, "person"), 0);
    teardown();
}

static void t_v08_resource_prep_failure(void)
{
    printf("V08 host fault during preparation rejected as resource, old config kept\n");
    setup();
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.target_class_name, "car", sizeof(cand.target_class_name));
    lcstub_fault(s, LCSTUB_FN_MODEL_META, LC_RET_IO_ERROR, 1);
    CHECK_EQ_I(push_apply(&cand, LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 49,
                          bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_RESOURCE);
    CHECK_EQ_I(lc_strcmp(bus.cfg.target_class_name, "person"), 0);
    CHECK_EQ_I(bus.st.state_commit_failures, 0u);
    teardown();
}

static void t_v09_commit_io_failure(void)
{
    printf("V09 apply commit IO failure -> FAILED_STORAGE_IO, RAM and stored state untouched (flush-defect fixed on v3 path)\n");
    setup();
    run_crossing(1, 500, 100);
    lcbus_flush(&bus, 1);
    uint8_t saved[LCSTUB_STATE_CAP];
    uint32_t saved_len = s->state_len;
    memcpy(saved, s->state_blob, saved_len);
    uint32_t rev0 = bus.revision;
    uint32_t total0 = bus.total_in;
    lc_bus_config_t cfg0 = bus.cfg;
    lcstub_fault(s, LCSTUB_FN_STATE_COMMIT, LC_RET_IO_ERROR, 1);
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "changed", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 50, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st, gen;
    CHECK_EQ_I(reply_status(0, &st, &gen, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_FAILED_STORAGE_IO);
    CHECK_EQ_I(gen, bus.config_generation);
    CHECK_EQ_I(bus.total_in, total0);
    CHECK_EQ_I(bus.revision, rev0);
    CHECK_EQ_I(lc_strcmp(bus.cfg.counter_name, cfg0.counter_name), 0);
    CHECK_EQ_I(s->state_len, saved_len);
    CHECK(memcmp(saved, s->state_blob, saved_len) == 0);
    CHECK_EQ_I(bus.st.state_commit_failures, 1u);
    CHECK_EQ_I(bus.storage_unknown_latch, 0);
    teardown();
}

static void t_v10_commit_conflict(void)
{
    printf("V10 apply commit revision conflict -> FAILED_STATE_CONFLICT, stored bytes win\n");
    setup();
    run_crossing(1, 500, 100);
    lcbus_flush(&bus, 1);
    uint8_t saved[LCSTUB_STATE_CAP];
    uint32_t saved_len = s->state_len;
    memcpy(saved, s->state_blob, saved_len);
    lcstub_set_state(s, saved, saved_len, bus.revision + 5u);
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "changed", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 51, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_FAILED_STATE_CONFLICT);
    CHECK_EQ_I(s->state_revision, bus.revision + 5u);
    CHECK_EQ_I(s->state_len, saved_len);
    CHECK(memcmp(saved, s->state_blob, saved_len) == 0);
    CHECK_EQ_I(ctrl.st.failed_state_conflict, 1u);
    teardown();
}

static void t_v11_storage_unknown_restricted(void)
{
    printf("V11 storage-unknown commit -> FAILED_STORAGE_UNKNOWN, restricted until verified\n");
    setup();
    run_crossing(1, 500, 100);
    lcbus_flush(&bus, 1);
    uint32_t total0 = bus.total_in;
    lcstub_fault(s, LCSTUB_FN_STATE_COMMIT, LC_RET_STORAGE_UNKNOWN, 1);
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "changed", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 52, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_FAILED_STORAGE_UNKNOWN);
    CHECK_EQ_I(bus.total_in, total0);
    CHECK_EQ_I(bus.storage_unknown_latch, 1);
    CHECK_EQ_I(ctrl.st.failed_storage_unknown, 1u);

    uint32_t commits_before = s->calls[LCSTUB_FN_STATE_COMMIT];
    CHECK_EQ_I(push_reset(LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 53,
                          bus.config_generation), 0);
    poll_ctrl();
    CHECK_EQ_I(reply_status(1, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_FAILED_STORAGE_UNKNOWN);
    CHECK_EQ_I(s->calls[LCSTUB_FN_STATE_COMMIT], commits_before);

    s->tick_now += 6000u;
    lcbus_flush(&bus, 0);
    CHECK_EQ_I(bus.storage_unknown_latch, 0);

    CHECK_EQ_I(push_reset(LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 54,
                          bus.config_generation), 0);
    poll_ctrl();
    CHECK_EQ_I(reply_status(2, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    teardown();
}

static void t_v12_dedup_cached(void)
{
    printf("V12 identical duplicate request reuses cached result, no redo\n");
    setup();
    run_crossing(1, 500, 100);
    lcbus_flush(&bus, 1);
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "renamed", sizeof(cand.counter_name));
    uint8_t payload[LC_CFG_CAND_SIZE];
    CHECK_EQ_I(lc_cfg_encode(payload, sizeof(payload), &cand), LC_CFG_CAND_SIZE);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                                       5, 60, bus.config_generation, 0,
                                       payload, sizeof(payload));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 60, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st, gen;
    CHECK_EQ_I(reply_status(0, &st, &gen, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    uint32_t commits = s->calls[LCSTUB_FN_STATE_COMMIT];
    uint32_t totals = bus.total_in;
    (void)cmd;
    (void)len;

    uint8_t cmd2[LC_CTRL_MSG_BUF_CAP];
    uint32_t len2 = lcstub_make_command(cmd2, sizeof(cmd2), LC_CTRL_TYPE_CONFIG_APPLY,
                                        5, 60, bus.config_generation - 1u, 0,
                                        payload, sizeof(payload));
    CHECK_EQ_I(len2, len);
    CHECK(memcmp(cmd, cmd2, len) == 0);
    CHECK_EQ_I(push_apply(&cand, 0, 5, 60, bus.config_generation - 1u), 0);
    poll_ctrl();
    CHECK_EQ_I(reply_status(1, &st, &gen, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(gen, 2u);
    CHECK_EQ_I(s->calls[LCSTUB_FN_STATE_COMMIT], commits);
    CHECK_EQ_I(bus.total_in, totals);
    CHECK_EQ_I(ctrl.st.dedup_cached, 1u);
    teardown();
}

static void t_v13_dedup_conflict(void)
{
    printf("V13 duplicate request_id with different semantics rejected, no data change\n");
    setup();
    run_crossing(1, 500, 100);
    lcbus_flush(&bus, 1);
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "renamed", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 61, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);

    lc_bus_config_t cand2 = bus.cfg;
    lc_strlcpy(cand2.counter_name, "other", sizeof(cand2.counter_name));
    CHECK_EQ_I(push_apply(&cand2, 0, 5, 61, bus.config_generation), 0);
    poll_ctrl();
    CHECK_EQ_I(reply_status(1, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_INVALID);
    CHECK_EQ_I(lc_strcmp(bus.cfg.counter_name, "renamed"), 0);
    CHECK_EQ_I(ctrl.st.dedup_conflict, 1u);
    teardown();
}

static void t_v14_wire_negatives(void)
{
    printf("V14 command wire negatives dropped without reply or commit\n");
    setup();
    uint32_t commits = s->calls[LCSTUB_FN_STATE_COMMIT];
    lc_bus_config_t cand = cfg_def();
    uint8_t payload[LC_CFG_CAND_SIZE];
    CHECK_EQ_I(lc_cfg_encode(payload, sizeof(payload), &cand), LC_CFG_CAND_SIZE);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];

    uint32_t len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                                       5, 70, 1u, 0, payload, sizeof(payload));
    cmd[0] ^= 0xFF;
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 71, 1u, 0, payload, sizeof(payload));
    cmd[4] = 2;
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), 5, 5, 72, 1u, 0, payload,
                              sizeof(payload));
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 73, 1u, 0, payload, sizeof(payload));
    lcstub_wr32(cmd + 8, len + 1u);
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              0, 74, 1u, 0, payload, sizeof(payload));
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 0, 1u, 0, payload, sizeof(payload));
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 75, 0u, 0, payload, sizeof(payload));
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 76, 1u, 0, payload, sizeof(payload));
    lcstub_wr32(cmd + 24, 9u);
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 77, 1u, 0, payload, sizeof(payload));
    lcstub_wr32(cmd + 28, 0x2u);
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_COUNTERS_RESET,
                              5, 78, 1u, LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED,
                              payload, 4u);
    lcstub_push_command(s, cmd, len);
    poll_ctrl();

    uint8_t empty[LC_CTRL_HEADER_SIZE];
    len = lcstub_make_command(empty, sizeof(empty), LC_CTRL_TYPE_CONFIG_APPLY,
                              5, 79, 1u, 0, NULL, 0u);
    lcstub_push_command(s, empty, len);
    poll_ctrl();

    CHECK_EQ_I(ctrl.st.wire_rejected, 11u);
    CHECK_EQ_I(ctrl.st.commands_received, 11u);
    CHECK_EQ_I(lcstub_reply_count(s), 0);
    CHECK_EQ_I(s->calls[LCSTUB_FN_STATE_COMMIT], commits);
    teardown();
}

static void t_v15_reset_happy(void)
{
    printf("V15 confirmed reset zeroes counters, keeps report_seq and generation\n");
    setup();
    run_crossing(1, 500, 100);
    bus.report_seq = 12;
    lcbus_flush(&bus, 1);
    uint32_t rev0 = bus.revision;
    CHECK_EQ_I(push_reset(LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 80,
                          bus.config_generation), 0);
    poll_ctrl();
    uint32_t st, gen, rev;
    CHECK_EQ_I(reply_status(0, &st, &gen, &rev, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(gen, bus.config_generation);
    CHECK_EQ_I(rev, rev0 + 1u);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK_EQ_I(bus.total_out, 0);
    CHECK_EQ_I(bus.window_in, 0);
    CHECK_EQ_I(bus.report_seq, 12u);
    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq, sgen;
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(ti, 0u);
    CHECK_EQ_I(seq, 12u);
    CHECK_EQ_I(sgen, 1u);
    teardown();
}

static void t_v16_corrupt_reset_recovery(void)
{
    printf("V16 corrupt stored state: confirmed reset replaces blob (v2 recovery kept)\n");
    setup();
    teardown();
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    uint8_t junk[200];
    memset(junk, 0xAB, sizeof(junk));
    lcstub_set_state(s, junk, sizeof(junk), 4);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    lcbus_rebind(&bus, 1);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_CORRUPT);
    CHECK(memcmp(junk, s->state_blob, sizeof(junk)) == 0);

    lc_bus_config_t cand = cfg_def();
    CHECK_EQ_I(push_apply(&cand, 0, 5, 81, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_FAILED_STORAGE_UNKNOWN);
    CHECK(memcmp(junk, s->state_blob, sizeof(junk)) == 0);

    CHECK_EQ_I(push_reset(LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED, 5, 82,
                          bus.config_generation), 0);
    poll_ctrl();
    CHECK_EQ_I(reply_status(1, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);
    teardown();
}

static void t_v18_degraded_refuses_apply(void)
{
    printf("V18 degraded storage refuses side-effect command\n");
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
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_DEGRADED);

    lc_bus_config_t cand = cfg_def();
    CHECK_EQ_I(push_apply(&cand, 0, 5, 83, bus.config_generation), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_FAILED_STORAGE_UNKNOWN);
    teardown();
}

static void t_v19_v2_migration(void)
{
    printf("V19 v2->v3 same-identity migration keeps counters/report_seq, gen initialized to 1\n");
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    seed_state_v2("legacy-counter", 7u, 8u, 42u, 3);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    lcbus_rebind(&bus, 1);
    CHECK_EQ_I(bus.total_in, 7u);
    CHECK_EQ_I(bus.total_out, 8u);
    CHECK_EQ_I(bus.report_seq, 42u);
    CHECK_EQ_I(bus.config_generation, 1u);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(lc_strcmp(bus.cfg.counter_name, "legacy-counter"), 0);

    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "migrated", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 84, 1u), 0);
    poll_ctrl();
    uint32_t st, gen;
    CHECK_EQ_I(reply_status(0, &st, &gen, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(gen, 2u);
    CHECK_EQ_I(bus.total_in, 7u);
    CHECK_EQ_I(bus.total_out, 8u);
    CHECK_EQ_I(bus.report_seq, 42u);
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);
    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq, sgen;
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(ti, 7u);
    CHECK_EQ_I(seq, 42u);
    CHECK_EQ_I(sgen, 2u);
    teardown();
}

static void t_v20_migration_corrupt_no_fake_restore(void)
{
    printf("V20 corrupt legacy blob not faked into trusted state\n");
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    uint8_t junk[152];
    memset(junk, 0x5C, sizeof(junk));
    lcstub_set_state(s, junk, sizeof(junk), 8);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_CORRUPT);
    CHECK_EQ_I(bus.total_in, 0);
    CHECK_EQ_I(bus.config_generation, 1u);
    CHECK(memcmp(junk, s->state_blob, sizeof(junk)) == 0);
    lcstub_destroy(s);
    s = NULL;
}

static void t_v21_session_authority(void)
{
    printf("V21 control_next authority: no command NO_EVENT; unauthorized session fatal\n");
    setup();
    uint32_t snaps = lcstub_snapshot_count(s);
    s->tick_now += 5000u;
    poll_ctrl();
    CHECK_EQ_I(lcstub_snapshot_count(s), snaps + 1);
    teardown();

    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
    lcstub_set_session(s, 0);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &tbl;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2;
    bus.config_generation = 1;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &tbl);
    CHECK_EQ_I(bus.session_fatal, 1);
    lcstub_destroy(s);
    s = NULL;
}

static void t_v22_oversized_payload_whole_reject(void)
{
    printf("V22 oversized candidate payload rejected whole, no partial effect\n");
    setup();
    run_crossing(1, 500, 100);
    uint8_t big[168];
    memset(big, 0x11, sizeof(big));
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                                       5, 90, bus.config_generation, 0, big,
                                       sizeof(big));
    CHECK_EQ_I(len, LC_CTRL_HEADER_SIZE + sizeof(big));
    lcstub_push_command(s, cmd, len);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_INVALID);
    CHECK_EQ_I(bus.total_in, 1);
    CHECK_EQ_I(s->calls[LCSTUB_FN_STATE_COMMIT], 0u);
    teardown();
}

static void t_v23_generation_exhaustion(void)
{
    printf("V23 config_generation u32 exhaustion is fail-closed resource rejection\n");
    setup();
    run_crossing(1, 500, 100);
    lcbus_flush(&bus, 1);
    bus.config_generation = 0xFFFFFFFFu;
    lc_bus_config_t cand = bus.cfg;
    lc_strlcpy(cand.counter_name, "overflow", sizeof(cand.counter_name));
    CHECK_EQ_I(push_apply(&cand, 0, 5, 91, 0xFFFFFFFFu), 0);
    poll_ctrl();
    uint32_t st;
    CHECK_EQ_I(reply_status(0, &st, NULL, NULL, NULL, NULL), 1);
    CHECK_EQ_I(st, LC_CTRL_RESULT_REJECTED_RESOURCE);
    CHECK_EQ_I(bus.config_generation, 0xFFFFFFFFu);
    CHECK_EQ_I(bus.total_in, 1);
    teardown();
}

int main(void)
{
    t_v01_stale_generation();
    t_v02_reset_unconfirmed();
    t_v03_target_change_unconfirmed();
    t_v04_apply_rename_keeps_counts();
    t_v05_line_change_boundary();
    t_v06_target_change_confirmed_resets();
    t_v07_target_missing_invalid();
    t_v08_resource_prep_failure();
    t_v09_commit_io_failure();
    t_v10_commit_conflict();
    t_v11_storage_unknown_restricted();
    t_v12_dedup_cached();
    t_v13_dedup_conflict();
    t_v14_wire_negatives();
    t_v15_reset_happy();
    t_v16_corrupt_reset_recovery();
    t_v18_degraded_refuses_apply();
    t_v19_v2_migration();
    t_v20_migration_corrupt_no_fake_restore();
    t_v21_session_authority();
    t_v22_oversized_payload_whole_reject();
    t_v23_generation_exhaustion();
    TEST_REPORT("ctrl-txn");
}
