
#include "test_common.h"
#include "lc_cfgcodec.h"
#include "lc_stateblob.h"
#include "lc_bus_config.h"
#include "host_stub.h"
#include "lc_compat.h"
#include "lc_app_abi_v3.h"

int g_pass = 0;
int g_fail = 0;

static lc_bus_config_t base_cfg(void)
{
    lc_bus_config_t c;
    lc_bus_config_defaults(&c);
    return c;
}

static const uint8_t *state_blob_shape(void)
{
    static uint8_t blob[LC_ST_BLOB_SIZE];
    lc_bus_config_t c = base_cfg();
    uint32_t n = lc_st_encode(blob, sizeof(blob), &c, 7u, 8u, 1u, 2u, 42u);
    if (n != LC_ST_BLOB_SIZE) return NULL;
    return blob;
}

static void t01_encode_decode_roundtrip(void)
{
    printf("U01 cfg candidate encode/decode roundtrip\n");
    lc_bus_config_t c = base_cfg();
    c.counter_name[0] = 'a';
    c.counter_name[1] = '\0';
    uint8_t buf[LC_CFG_CAND_SIZE];
    CHECK_EQ_I(lc_cfg_encode(buf, sizeof(buf), &c), LC_CFG_CAND_SIZE);
    lc_bus_config_t out;
    CHECK_EQ_I(lc_cfg_decode(buf, sizeof(buf), &out), LC_CFG_OK);
    CHECK_EQ_I(lc_strcmp(out.counter_name, c.counter_name), 0);
    CHECK_EQ_I(lc_strcmp(out.target_class_name, c.target_class_name), 0);
    CHECK_EQ_I(out.line_x1_permille, c.line_x1_permille);
    CHECK_EQ_I(out.line_y2_permille, c.line_y2_permille);
    CHECK_EQ_I(out.outside_x_permille, c.outside_x_permille);
    CHECK_EQ_I(out.outside_y_permille, c.outside_y_permille);
    CHECK_EQ_I(out.conf_threshold_permille, c.conf_threshold_permille);
    CHECK_EQ_I(out.max_dist_permille, c.max_dist_permille);
    CHECK_EQ_I(out.track_history_k, c.track_history_k);
    CHECK_EQ_I(out.max_miss, c.max_miss);
    CHECK_EQ_I(out.k_confirm, c.k_confirm);
    CHECK_EQ_I(out.window_minutes, c.window_minutes);
    CHECK_EQ_I(out.tracks_report_enable, c.tracks_report_enable);
    CHECK_EQ_I(out.heat_grid_enable, c.heat_grid_enable);
}

static void t02_worst_case_names(void)
{
    printf("U02 worst-case legal names encode/decode\n");
    lc_bus_config_t c = base_cfg();
    for (int i = 0; i < 21; i++) {
        c.counter_name[i * 3 + 0] = (char)0xe5;
        c.counter_name[i * 3 + 1] = (char)0xae;
        c.counter_name[i * 3 + 2] = (char)0xb8;
    }
    c.counter_name[63] = '\0';
    const char *tmax = "abcdefghijklmnopqrstuvwxyz01234";
    lc_strlcpy(c.target_class_name, tmax, sizeof(c.target_class_name));
    uint8_t buf[LC_CFG_CAND_SIZE];
    CHECK_EQ_I(lc_cfg_encode(buf, sizeof(buf), &c), LC_CFG_CAND_SIZE);
    lc_bus_config_t out;
    CHECK_EQ_I(lc_cfg_decode(buf, sizeof(buf), &out), LC_CFG_OK);
    CHECK_EQ_I(lc_strlen(out.counter_name), 63u);
    CHECK_EQ_I(lc_strlen(out.target_class_name), 31u);
}

static void t02_rejects(void)
{
    printf("U03 candidate negative vectors\n");
    lc_bus_config_t c = base_cfg();
    uint8_t buf[LC_CFG_CAND_SIZE];
    uint8_t bad[LC_CFG_CAND_SIZE];
    lc_bus_config_t out;
    CHECK_EQ_I(lc_cfg_encode(buf, sizeof(buf), &c), LC_CFG_CAND_SIZE);

    memcpy(bad, buf, sizeof(bad));
    bad[0] ^= 0xFF;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_MAGIC);

    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 4, LC_CFG_SCHEMA + 1u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_SCHEMA);

    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 8, LC_CFG_CAND_SIZE - 1u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_SIZE);
    CHECK_EQ_I(lc_cfg_decode(buf, LC_CFG_CAND_SIZE - 1u, &out), LC_CFG_ERR_SIZE);

    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 12, 1u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_FLAGS);
    lcstub_wr32(bad + 136, 1u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_FLAGS);
    memcpy(bad, buf, sizeof(bad));
    bad[140] = 1u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_FLAGS);

    memcpy(bad, buf, sizeof(bad));
    bad[16] = 0u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_NAME);
    memcpy(bad, buf, sizeof(bad));
    bad[16] = 32u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_NAME);
    memcpy(bad, buf, sizeof(bad));
    bad[17 + 5] = 0x22u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_NAME);
    memcpy(bad, buf, sizeof(bad));
    bad[17 + 5] = 'x';
    bad[17 + 6] = 0x80u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_NAME);
    memcpy(bad, buf, sizeof(bad));
    bad[49] = 0u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_NAME);

    memcpy(bad, buf, sizeof(bad));
    bad[133] = 0x04u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_FLAGS);

    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 114, 1001u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_CONTENT);
    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 128, 1001u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_CONTENT);
    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 134, 1441u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_CONTENT);
    memcpy(bad, buf, sizeof(bad));
    lcstub_wr32(bad + 120, 1001u);
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_CONTENT);
    memcpy(bad, buf, sizeof(bad));
    bad[132] = 0u;
    CHECK_EQ_I(lc_cfg_decode(bad, sizeof(bad), &out), LC_CFG_ERR_CONTENT);

    const uint8_t *sb = state_blob_shape();
    CHECK(sb != NULL);
    if (sb) {
        CHECK_EQ_I(lc_cfg_decode(sb, LC_ST_BLOB_SIZE, &out), LC_CFG_ERR_STATE_BLOB);
    }
    CHECK_EQ_I(lc_cfg_status_name(LC_CFG_ERR_STATE_BLOB) != NULL, 1);
}

static void t03_stateblob_gen(void)
{
    printf("U04 state blob gen schema encode/decode + v2 compatibility\n");
    lc_bus_config_t c = base_cfg();
    uint8_t buf[LC_ST_BLOB_MAX];
    CHECK_EQ_I(lc_st_encode_gen(buf, sizeof(buf), &c, 11u, 12u, 3u, 4u, 55u, 7u),
               LC_ST_BLOB_SIZE_GEN);
    lc_bus_config_t out;
    uint32_t ti, to, wi, wo, seq, gen;
    CHECK_EQ_I(lc_st_decode_gen(buf, LC_ST_BLOB_SIZE_GEN, &out, &ti, &to, &wi, &wo,
                                &seq, &gen), LC_ST_OK);
    CHECK_EQ_I(ti, 11u);
    CHECK_EQ_I(to, 12u);
    CHECK_EQ_I(wi, 3u);
    CHECK_EQ_I(wo, 4u);
    CHECK_EQ_I(seq, 55u);
    CHECK_EQ_I(gen, 7u);

    CHECK_EQ_I(lc_st_encode_gen(buf, sizeof(buf), &c, 0u, 0u, 0u, 0u, 0u, 0u), 0u);
    CHECK_EQ_I(lc_st_decode_gen(buf, LC_ST_BLOB_SIZE_GEN - 1u, &out, &ti, &to, &wi,
                                &wo, &seq, &gen), LC_ST_ERR_SIZE);
    uint8_t v2buf[LC_ST_BLOB_SIZE_GEN];
    (void)lc_st_encode(v2buf, sizeof(v2buf), &c, 1u, 2u, 0u, 0u, 5u);
    CHECK_EQ_I(lc_st_decode_gen(v2buf, sizeof(v2buf), &out, &ti, &to, &wi, &wo,
                                &seq, &gen), LC_ST_ERR_SCHEMA);
    uint8_t gen_blob[LC_ST_BLOB_SIZE_GEN];
    (void)lc_st_encode_gen(gen_blob, sizeof(gen_blob), &c, 1u, 2u, 0u, 0u, 5u, 9u);
    CHECK_EQ_I(lc_st_decode(gen_blob, LC_ST_BLOB_SIZE_GEN, &out, &ti, &to, &wi, &wo,
                            &seq), LC_ST_ERR_SCHEMA);

    uint8_t v2[LC_ST_BLOB_SIZE];
    CHECK_EQ_I(lc_st_encode(v2, sizeof(v2), &c, 21u, 22u, 5u, 6u, 77u), LC_ST_BLOB_SIZE);
    CHECK_EQ_I(lc_st_decode(v2, sizeof(v2), &out, &ti, &to, &wi, &wo, &seq), LC_ST_OK);
    CHECK_EQ_I(ti, 21u);
    CHECK_EQ_I(seq, 77u);
    v2[20] ^= 0xFF;
    CHECK_EQ_I(lc_st_decode(v2, sizeof(v2), &out, &ti, &to, &wi, &wo, &seq),
               LC_ST_ERR_CRC);
}

static void t04_json_validator(void)
{
    printf("U05 host snapshot JSON boundary validator\n");
    const char *ok1 = "{\"a\":1,\"b\":{\"c\":\"x\"},\"d\":[1,2,3],\"e\":true,\"f\":null}";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)ok1, (uint32_t)strlen(ok1)), 1);
    const char *ok2 = "{\"n\":\"\\u4e2d\\u6587 \\\"q\\\"\"}";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)ok2, (uint32_t)strlen(ok2)), 1);
    const char *dup = "{\"a\":1,\"a\":2}";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)dup, (uint32_t)strlen(dup)), 0);
    const char *trail = "{\"a\":1} tail";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)trail, (uint32_t)strlen(trail)), 0);
    const char *arr = "[1,2]";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)arr, (uint32_t)strlen(arr)), 0);
    const char *nan = "{\"a\":NaN}";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)nan, (uint32_t)strlen(nan)), 0);
    const char *inf = "{\"a\":-Infinity}";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)inf, (uint32_t)strlen(inf)), 0);
    const uint8_t badutf8[] = { 0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0xFF, 0xFE, 0x22, 0x7D };
    CHECK_EQ_I(lcstub_snapshot_valid_json(badutf8, sizeof(badutf8)), 0);
    const char *nested_dup = "{\"o\":{\"k\":1,\"k\":2}}";
    CHECK_EQ_I(lcstub_snapshot_valid_json((const uint8_t *)nested_dup,
                                          (uint32_t)strlen(nested_dup)), 0);
}

int main(void)
{
    t01_encode_decode_roundtrip();
    t02_worst_case_names();
    t02_rejects();
    t03_stateblob_gen();
    t04_json_validator();
    TEST_REPORT("unit-v3");
}
