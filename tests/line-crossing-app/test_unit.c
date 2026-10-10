
#include "test_common.h"
#include "lc_arena.h"
#include "lc_json.h"
#include "lc_stateblob.h"
#include "lc_bus_config.h"

int g_pass = 0;
int g_fail = 0;

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void test_arena(void)
{
    printf("test_arena\n");
    lcapp_arena_init();
    CHECK_EQ_I(lcapp_arena_used(), 0);

    void *a = lcapp_alloc(100);
    void *b = lcapp_alloc(200);
    CHECK(a != NULL);
    CHECK(b != NULL);
    CHECK(((uintptr_t)a % 8u) == 0);
    CHECK(((uintptr_t)b % 8u) == 0);
    CHECK_EQ_I(lcapp_arena_used(), 8 + 104 + 8 + 200);

    lcapp_free(a);
    lcapp_free(b);
    CHECK_EQ_I(lcapp_arena_used(), 0);

    void *c = lcapp_alloc(300);
    CHECK(c != NULL);
    lcapp_free(c);

    void *z = lcapp_alloc(0);
    CHECK(z != NULL);
    lcapp_free(z);

    void *big = lcapp_alloc(LC_ARENA_SIZE);
    CHECK(big == NULL);

    lcapp_arena_init();
    void *slots[32];
    for (int i = 0; i < 32; i++) slots[i] = lcapp_alloc(1000 + (size_t)i * 8);
    int ok = 1;
    for (int i = 0; i < 32; i++) if (!slots[i]) ok = 0;
    CHECK(ok);
    for (int i = 0; i < 32; i += 2) lcapp_free(slots[i]);
    for (int i = 0; i < 32; i += 2) slots[i] = lcapp_alloc(1000);
    ok = 1;
    for (int i = 0; i < 32; i++) if (!slots[i]) ok = 0;
    CHECK(ok);
    for (int i = 0; i < 32; i++) lcapp_free(slots[i]);
    CHECK_EQ_I(lcapp_arena_used(), 0);
    CHECK(lcapp_arena_high_water() > 0);
}

static void test_json(void)
{
    printf("test_json\n");
    char buf[128];
    lc_json_t j;

    lcj_init(&j, buf, sizeof(buf));
    lcj_raw(&j, "{\"a\":");
    lcj_u32(&j, 4294967295u);
    lcj_raw(&j, ",\"b\":");
    lcj_i32(&j, -2147483647 - 1);
    lcj_raw(&j, ",\"c\":");
    lcj_bool(&j, 1);
    lcj_raw(&j, ",\"d\":");
    lcj_null(&j);
    lcj_raw(&j, ",\"e\":");
    lcj_string(&j, "a\"b\\c\n");
    lcj_raw(&j, ",\"f\":");
    lcj_permille(&j, 250);
    lcj_raw(&j, ",\"g\":");
    lcj_permille(&j, 1000);
    lcj_raw(&j, "}");
    CHECK_EQ_I(j.overflow, 0);
    buf[j.len] = '\0';
    CHECK(strcmp(buf, "{\"a\":4294967295,\"b\":-2147483648,\"c\":true,\"d\":null,"
                      "\"e\":\"a\\\"b\\\\c\\u000a\",\"f\":0.250,\"g\":1.000}") == 0);

    char small[8];
    lcj_init(&j, small, sizeof(small));
    lcj_string(&j, "1234567890");
    CHECK_EQ_I(j.overflow, 1);
    lcj_u32(&j, 12345);
    CHECK_EQ_I(j.len, 7);
}

static void test_stateblob(void)
{
    printf("test_stateblob\n");
    uint8_t buf[LC_ST_BLOB_MAX];
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    snprintf(cfg.counter_name, sizeof(cfg.counter_name), "\xe5\xae\xa2\xe6\xb5\x81-1");
    cfg.window_minutes = 3;
    cfg.tracks_report_enable = 1;

    uint32_t len = lc_st_encode(buf, sizeof(buf), &cfg, 11, 7, 3, 4, 41);
    CHECK_EQ_I(len, 152);

    lc_bus_config_t out;
    uint32_t ti, to, wi, wo, seq;
    CHECK_EQ_I(lc_st_decode(buf, len, &out, &ti, &to, &wi, &wo, &seq), LC_ST_OK);
    CHECK(strcmp(out.counter_name, cfg.counter_name) == 0);
    CHECK(strcmp(out.target_class_name, "person") == 0);
    CHECK_EQ_I(out.window_minutes, 3);
    CHECK_EQ_I(out.line_x1_permille, 200);
    CHECK_EQ_I(out.k_confirm, 5);
    CHECK_EQ_I(ti, 11); CHECK_EQ_I(to, 7);
    CHECK_EQ_I(wi, 3); CHECK_EQ_I(wo, 4);
    CHECK_EQ_I(seq, 41);

    CHECK_EQ_I(lc_st_decode(buf, len - 1, &out, &ti, &to, &wi, &wo, &seq), LC_ST_ERR_SIZE);
    CHECK_EQ_I(lc_st_decode(buf + 1, len, &out, &ti, &to, &wi, &wo, &seq), LC_ST_ERR_MAGIC);
    uint8_t bad[LC_ST_BLOB_MAX];
    memcpy(bad, buf, len);
    wr32(bad + 4, 99);
    CHECK_EQ_I(lc_st_decode(bad, len, &out, &ti, &to, &wi, &wo, &seq), LC_ST_ERR_SCHEMA);
    memcpy(bad, buf, len);
    bad[20] ^= 0x40;
    CHECK_EQ_I(lc_st_decode(bad, len, &out, &ti, &to, &wi, &wo, &seq), LC_ST_ERR_CRC);

    lc_bus_config_t inv;
    lc_bus_config_defaults(&inv);
    inv.target_class_name[0] = '\0';
    len = lc_st_encode(bad, sizeof(bad), &inv, 0, 0, 0, 0, 0);
    CHECK_EQ_I(len, 152);
    CHECK_EQ_I(lc_st_decode(bad, len, &out, &ti, &to, &wi, &wo, &seq), LC_ST_ERR_CONTENT);

    uint8_t tiny[16];
    CHECK_EQ_I(lc_st_encode(tiny, sizeof(tiny), &cfg, 0, 0, 0, 0, 0), 0);
}

static void test_config(void)
{
    printf("test_config\n");
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    CHECK_EQ_I(lc_bus_config_valid(&cfg), 1);
    CHECK(strcmp(cfg.target_class_name, "person") == 0);
    CHECK_EQ_I(cfg.window_minutes, 5);
    CHECK_EQ_I(cfg.conf_threshold_permille, 250);

    cfg.window_minutes = 0;
    CHECK_EQ_I(lc_bus_config_valid(&cfg), 0);
    lc_bus_config_defaults(&cfg);
    cfg.max_dist_permille = 0;
    CHECK_EQ_I(lc_bus_config_valid(&cfg), 0);
    lc_bus_config_defaults(&cfg);
    cfg.line_x1_permille = 1001;
    CHECK_EQ_I(lc_bus_config_valid(&cfg), 0);
    lc_bus_config_defaults(&cfg);
    cfg.track_history_k = 3;
    CHECK_EQ_I(lc_bus_config_valid(&cfg), 0);
    lc_bus_config_defaults(&cfg);
    cfg.target_class_name[0] = '\0';
    CHECK_EQ_I(lc_bus_config_valid(&cfg), 0);

    CHECK_EQ_I(lc_bus_utf8_valid("person"), 1);
    CHECK_EQ_I(lc_bus_utf8_valid("\xe5\xae\xa2\xe6\xb5\x81"), 1);
    CHECK_EQ_I(lc_bus_utf8_valid("\xff\xfe"), 0);
    CHECK_EQ_I(lc_bus_utf8_valid("\xe5\xae"), 0);
}

int main(void)
{
    test_arena();
    test_json();
    test_stateblob();
    test_config();
    TEST_REPORT("test_unit");
}
