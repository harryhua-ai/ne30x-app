#include "test_common.h"
#include "host_stub.h"
#include "lc_app_entry_v4.h"
#include "lc_ctrl.h"
#include "lc_stateblob.h"

int g_pass = 0;
int g_fail = 0;

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t make_enable(uint8_t *out, uint32_t session, uint32_t request,
                            uint32_t desired, uint32_t revision)
{
    memset(out, 0, LC_CTRL_V4_ENABLE_SET_SIZE);
    lcstub_wr32(out, LC_CTRL_V4_PROTO_MAGIC);
    out[4] = 1u;
    out[6] = (uint8_t)LC_CTRL_V4_TYPE_ENABLE_SET;
    lcstub_wr32(out + 8u, LC_CTRL_V4_ENABLE_SET_SIZE);
    lcstub_wr32(out + 12u, session);
    lcstub_wr32(out + 16u, request);
    lcstub_wr32(out + 20u, 1u);
    lcstub_wr32(out + 32u, LC_CTRL_V4_ENABLE_MAGIC);
    lcstub_wr32(out + 36u, desired);
    lcstub_wr32(out + 40u, revision);
    return LC_CTRL_V4_ENABLE_SET_SIZE;
}

static void test_entry_rejects_bad_v4_contract(void)
{
    CHECK_EQ_I(app_entry(NULL, LC_APP_ABI_V4), LC_APP_EXIT_BAD_API);
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcstub_make_table_v4(stub, &api);
    api.table_size = LC_APP_API_V3_TABLE_SIZE;
    CHECK_EQ_I(app_entry(&api, LC_APP_ABI_V4), LC_APP_EXIT_BAD_TABLE);
    api.table_size = LC_APP_API_V4_TABLE_SIZE;
    CHECK_EQ_I(app_entry(&api, LC_APP_ABI_V3), LC_APP_EXIT_BAD_ABI);
    api.live_publish = NULL;
    CHECK_EQ_I(app_entry(&api, LC_APP_ABI_V4), LC_APP_EXIT_BAD_FNPTR);
    lcstub_destroy(stub);
}

static void test_entry_runs_paused_session_without_revision_bump(void)
{
    lcstub_t *stub = lcstub_new();
    stub->auto_stop_after_no_events = 1u;
    lc_app_api_v4_t api;
    lcstub_make_table_v4(stub, &api);
    uint8_t cmd[LC_CTRL_V4_ENABLE_SET_SIZE];
    uint32_t len = make_enable(cmd, 91u, 600u, LC_ST_ENABLE_PAUSED, 1u);
    lcstub_push_command(stub, cmd, len);
    CHECK_EQ_I(app_entry(&api, LC_APP_ABI_V4), LC_APP_EXIT_OK);
    CHECK_EQ_I(stub->state_revision, 2u);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 2u);
    CHECK_EQ_I(lcstub_reply_count(stub), 1);
    CHECK_EQ_I(stub->replies[0].len, LC_CTRL_V4_ENABLE_RECEIPT_SIZE);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 28u), LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 24u), stub->state_revision);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 40u), stub->state_revision);
    lc_bus_config_t cfg;
    uint32_t ti, to, wi, wo, seq, gen, enable, source;
    CHECK_EQ_I(lc_st_decode_enable(stub->state_blob, stub->state_len, &cfg,
                                   &ti, &to, &wi, &wo, &seq, &gen,
                                   &enable, &source), LC_ST_OK);
    CHECK_EQ_I(enable, LC_ST_ENABLE_PAUSED);
    CHECK_EQ_I(source, LC_ST_BLOB_SCHEMA_ENABLE);
    lcstub_destroy(stub);
}

int main(void)
{
    test_entry_rejects_bad_v4_contract();
    test_entry_runs_paused_session_without_revision_bump();
    TEST_REPORT("line-crossing-enable-entry-v4");
}
