
#include "test_common.h"
#include "host_stub.h"
#include "lc_bus.h"
#include "lc_ctrl.h"
#include "lc_stateblob.h"
#include "lc_cfgcodec.h"
#include "lc_app_entry_v3.h"
#include "lc_compat.h"

int g_pass = 0;
int g_fail = 0;

static lcstub_t *s;
static lc_app_api_v3_t tbl;

static void setup(void)
{
    s = lcstub_new();
    lcstub_make_table_v3(s, &tbl);
    lcstub_set_model(s, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(s, 0, "person");
    lcstub_set_class(s, 1, "car");
}

static void teardown(void)
{
    lcstub_destroy(s);
    s = NULL;
}

static void push_apply_cmd(const lc_bus_config_t *cand, uint32_t flags,
                           uint32_t session, uint32_t req, uint32_t expected_gen)
{
    uint8_t payload[LC_CFG_CAND_SIZE];
    CHECK_EQ_I(lc_cfg_encode(payload, sizeof(payload), cand), LC_CFG_CAND_SIZE);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = lcstub_make_command(cmd, sizeof(cmd), LC_CTRL_TYPE_CONFIG_APPLY,
                                       session, req, expected_gen, flags,
                                       payload, sizeof(payload));
    CHECK_EQ_I(len, LC_CTRL_HEADER_SIZE + LC_CFG_CAND_SIZE);
    lcstub_push_command(s, cmd, len);
    printf("CONFIG_APPLY_OCCUPANCY total=%u declared_max=%u\n", len,
           LC_CTRL_CONTROL_MAX_DECLARED);
}

static void c01_entry_validation(void)
{
    printf("C01 v3 entry validation (api/table/abi/fnptr)\n");
    setup();
    CHECK_EQ_I(app_entry(NULL, LC_APP_ABI_V3), LC_APP_EXIT_BAD_API);

    tbl.table_size = 48u;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_BAD_TABLE);
    tbl.table_size = 64u;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_BAD_TABLE);
    tbl.table_size = LC_APP_API_V3_TABLE_SIZE;

    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V2), LC_APP_EXIT_BAD_ABI);

    lc_app_fn_control_next_t saved = tbl.control_next;
    tbl.control_next = NULL;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_BAD_FNPTR);
    tbl.control_next = saved;
    teardown();
}

static void c02_session_with_command(void)
{
    printf("C02 v3 session: command consumed mid-session, applied, replied, snapshotted\n");
    setup();
    lc_bus_config_t cand;
    lc_bus_config_defaults(&cand);
    lc_strlcpy(cand.counter_name, "hot-configured", sizeof(cand.counter_name));
    push_apply_cmd(&cand, 0, 5, 42, 1u);
    s->auto_stop_after_no_events = 2;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_OK);

    CHECK_EQ_I(lcstub_reply_count(s), 1);
    const uint8_t *r = lcstub_reply(s, 0);
    CHECK(r != NULL);
    if (r) {
        CHECK_EQ_I(r[LC_CTRL_OFF_MSG_TYPE], LC_CTRL_TYPE_REPLY);
        CHECK_EQ_I(lc_rd_u32(r + LC_CTRL_OFF_FLAGS), LC_CTRL_RESULT_APPLIED);
        CHECK_EQ_I(lc_rd_u32(r + LC_CTRL_OFF_CONFIG_GENERATION), 2u);
        CHECK_EQ_I(lc_rd_u32(r + LC_CTRL_OFF_SESSION_GENERATION), 5u);
        CHECK_EQ_I(lc_rd_u32(r + LC_CTRL_OFF_REQUEST_ID), 42u);
    }
    CHECK_EQ_I(s->calls[LCSTUB_FN_CONTROL_NEXT] >= 1u, 1);
    CHECK_EQ_I(lcstub_snapshot_count(s) >= 1, 1);
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);
    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq, sgen;
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(sgen, 2u);
    CHECK_EQ_I(lc_strcmp(scfg.counter_name, "hot-configured"), 0);
    teardown();
}

static void c03_migration_and_restart(void)
{
    printf("C03 v2 blob migrated in v3 session and survives restart without fake reset\n");
    setup();
    lc_bus_config_t c;
    lc_bus_config_defaults(&c);
    lc_strlcpy(c.counter_name, "legacy", sizeof(c.counter_name));
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t n = lc_st_encode(blob, sizeof(blob), &c, 5u, 6u, 0u, 0u, 33u);
    CHECK_EQ_I(n, LC_ST_BLOB_SIZE);
    lcstub_set_state(s, blob, n, 2);
    s->auto_stop_after_no_events = 2;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_OK);
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);

    lc_bus_config_t scfg;
    uint32_t ti, to, wi, wo, seq, sgen;
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(ti, 5u);
    CHECK_EQ_I(to, 6u);
    CHECK_EQ_I(seq, 33u);
    CHECK_EQ_I(sgen, 1u);

    s->auto_stop_after_no_events = 2;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_OK);
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);
    CHECK_EQ_I(lc_st_decode_gen(s->state_blob, s->state_len, &scfg, &ti, &to, &wi,
                                &wo, &seq, &sgen), LC_ST_OK);
    CHECK_EQ_I(ti, 5u);
    CHECK_EQ_I(to, 6u);
    CHECK_EQ_I(seq, 33u);
    teardown();
}

static void c04_event_stream_and_command(void)
{
    printf("C04 command consumed without interrupting continuous event stream\n");
    setup();
    static const float ys[4] = { 0.30f, 0.44f, 0.58f, 0.72f };
    for (int i = 0; i < 8; i++) {
        lcstub_det_t d = { 0.45f, ys[i % 4] - 0.02f, 0.1f, 0.04f, 0.9f, 0 };
        lcstub_push_frame(s, (uint32_t)i, (uint32_t)i * 100u, 7, 3, 0, 0, &d, 1);
    }
    lc_bus_config_t cand;
    lc_bus_config_defaults(&cand);
    lc_strlcpy(cand.counter_name, "midstream", sizeof(cand.counter_name));
    push_apply_cmd(&cand, 0, 5, 43, 1u);
    s->auto_stop_after_no_events = 2;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_OK);
    CHECK_EQ_I(lcstub_reply_count(s), 1);
    const uint8_t *r = lcstub_reply(s, 0);
    CHECK(r != NULL);
    if (r) {
        CHECK_EQ_I(lc_rd_u32(r + LC_CTRL_OFF_FLAGS), LC_CTRL_RESULT_APPLIED);
    }
    CHECK_EQ_I(s->state_len, LC_ST_BLOB_SIZE_GEN);
    teardown();
}

static void c05_unauthorized_control_ends_session(void)
{
    printf("C05 unauthorized control plane ends session fail-closed\n");
    setup();
    s->ctrl_unauthorized = 1;
    s->auto_stop_after_no_events = 2;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_UNAUTHORIZED);
    teardown();
}

static void c06_reply_quota_and_mismatch_visible(void)
{
    printf("C06 host-visible reply/snapshot wire rejects stay observable\n");
    setup();
    CHECK_EQ_I(s->reply_wire_rejects, 0u);
    CHECK_EQ_I(s->snapshot_wire_rejects, 0u);
    s->auto_stop_after_no_events = 2;
    CHECK_EQ_I(app_entry(&tbl, LC_APP_ABI_V3), LC_APP_EXIT_OK);
    CHECK_EQ_I(s->reply_wire_rejects, 0u);
    CHECK_EQ_I(s->snapshot_wire_rejects, 0u);
    CHECK(lcstub_snapshot_count(s) >= 1);
    teardown();
}

int main(void)
{
    c01_entry_validation();
    c02_session_with_command();
    c03_migration_and_restart();
    c04_event_stream_and_command();
    c05_unauthorized_control_ends_session();
    c06_reply_quota_and_mismatch_visible();
    TEST_REPORT("contract-v3");
}
