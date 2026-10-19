#include "test_common.h"
#include "host_stub.h"
#include "lc_bus.h"
#include "lc_stateblob.h"
#include "lc_ctrl.h"
#include "lc_cfgcodec.h"

int g_pass = 0;
int g_fail = 0;

__attribute__((weak))
int lcbus_enable_set(lcbus_t *bus, uint32_t desired_state,
                     uint32_t expected_config_generation,
                     uint32_t expected_state_revision,
                     uint32_t *out_revision)
{
    (void)bus;
    (void)desired_state;
    (void)expected_config_generation;
    (void)expected_state_revision;
    (void)out_revision;
    return -99;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t test_crc32(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint32_t bit = 0; bit < 8; bit++) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t make_paused_schema3(uint8_t *blob, uint32_t cap)
{
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    uint32_t len = lc_st_encode_gen(blob, cap, &cfg, 7u, 4u, 2u, 1u, 9u, 1u);
    if (len != 160u) return 0u;
    wr32(blob + 4u, 3u);
    wr32(blob + 156u, 2u);
    wr32(blob + 8u, test_crc32(blob + 12u, len - 12u));
    return len;
}

static void deliver_path(lcstub_t *stub, lcbus_t *bus, const float *y,
                         uint32_t count, uint32_t start_ms)
{
    for (uint32_t i = 0; i < count; i++) {
        lcstub_det_t detection = { 0.45f, y[i] - 0.02f, 0.1f, 0.04f, 0.9f, 0u };
        lcstub_push_frame(stub, i + 1u, start_ms + i * 100u, 7u, 3u,
                          0u, 0u, &detection, 1u);
        uint8_t event[LC_APP_EVENT_BUF_CAP];
        int slot = stub->ev_head;
        uint32_t len = stub->event_len[slot];
        memcpy(event, stub->events[slot], len);
        stub->ev_head = (stub->ev_head + 1) % LCSTUB_MAX_EVENTS;
        stub->ev_count--;
        lcbus_on_event(bus, event, len);
    }
}

static void deliver_crossing(lcstub_t *stub, lcbus_t *bus)
{
    static const float y[] = { 0.30f, 0.44f, 0.58f, 0.72f };
    deliver_path(stub, bus, y, 4u, 100u);
}

static void test_v3_corrupt_paused_state_blocks_frame_and_idle(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v2_t api;
    lcstub_make_table(stub, &api);
    lcstub_set_model(stub, 1, 7u, 3u, 1u, "od-demo", "1.2");
    lcstub_set_class(stub, 0u, "person");

    uint8_t paused[LC_ST_BLOB_MAX];
    uint32_t paused_len = make_paused_schema3(paused, sizeof(paused));
    lcstub_set_state(stub, paused, paused_len, 6u);

    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &api;
    lcbus_t bus;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2u;
    bus.config_generation = 1u;
    lcbus_restore(&bus);
    lcbus_rebind(&bus, 1);

    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_CORRUPT);
    deliver_crossing(stub, &bus);
    CHECK_EQ_I(bus.total_in, 0u);
    CHECK_EQ_I(bus.total_out, 0u);
    CHECK_EQ_I(bus.window_in, 0u);
    CHECK_EQ_I(bus.window_out, 0u);

    lcstub_set_tick(stub, 300001u);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_REPORT_SUBMIT), 0u);
    CHECK_EQ_I(bus.report_seq, 0u);

    lcstub_destroy(stub);
}

static void test_v4_paused_schema3_restores_and_blocks_frame(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v2_t api;
    lcstub_make_table(stub, &api);
    lcstub_set_model(stub, 1, 7u, 3u, 1u, "od-demo", "1.2");
    lcstub_set_class(stub, 0u, "person");

    uint8_t paused[LC_ST_BLOB_MAX];
    uint32_t paused_len = make_paused_schema3(paused, sizeof(paused));
    lcstub_set_state(stub, paused, paused_len, 6u);

    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &api;
    lcbus_t bus;
    lcbus_init(&bus, &ops);
    bus.state_schema = 3u;
    bus.config_generation = 1u;
    lcbus_restore(&bus);
    lcbus_rebind(&bus, 1);

    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(bus.total_in, 7u);
    CHECK_EQ_I(bus.total_out, 4u);
    CHECK_EQ_I(bus.window_in, 2u);
    CHECK_EQ_I(bus.window_out, 1u);
    deliver_crossing(stub, &bus);
    CHECK_EQ_I(bus.total_in, 7u);
    CHECK_EQ_I(bus.total_out, 4u);
    CHECK_EQ_I(bus.window_in, 2u);
    CHECK_EQ_I(bus.window_out, 1u);

    lcstub_destroy(stub);
}

static void test_legacy_migration_commits_once(uint32_t schema)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v2_t api;
    lcstub_make_table(stub, &api);

    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    cfg.window_minutes = 17u;
    uint8_t legacy[LC_ST_BLOB_MAX];
    uint32_t legacy_len;
    if (schema == 1u) {
        legacy_len = lc_st_encode(legacy, sizeof(legacy), &cfg,
                                  121u, 45u, 7u, 9u, 13u);
    } else {
        legacy_len = lc_st_encode_gen(legacy, sizeof(legacy), &cfg,
                                      121u, 45u, 7u, 9u, 13u, 9u);
    }
    lcstub_set_state(stub, legacy, legacy_len, 12u);

    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &api;
    lcbus_t first;
    lcbus_init(&first, &ops);
    first.state_schema = 3u;
    first.enable_state = LCBUS_ENABLE_UNKNOWN;
    first.config_generation = 1u;
    lcbus_restore(&first);

    CHECK_EQ_I(first.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(first.enable_state, LCBUS_ENABLE_ENABLED);
    CHECK_EQ_I(first.total_in, 121u);
    CHECK_EQ_I(first.total_out, 45u);
    CHECK_EQ_I(first.window_in, 7u);
    CHECK_EQ_I(first.window_out, 9u);
    CHECK_EQ_I(first.report_seq, 13u);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 1u);
    CHECK_EQ_I(stub->state_revision, 13u);
    CHECK_EQ_I(rd32(stub->state_blob + 4u), 3u);

    lcbus_t second;
    lcbus_init(&second, &ops);
    second.state_schema = 3u;
    second.enable_state = LCBUS_ENABLE_UNKNOWN;
    second.config_generation = 1u;
    lcbus_restore(&second);
    CHECK_EQ_I(second.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(second.enable_state, LCBUS_ENABLE_ENABLED);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 1u);

    lcstub_destroy(stub);
}

static void test_schema3_codec_and_failures(void)
{
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    cfg.window_minutes = 17u;
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len = lc_st_encode_enable(blob, sizeof(blob), &cfg,
                                       121u, 45u, 7u, 9u, 13u, 9u,
                                       LC_ST_ENABLE_PAUSED);
    CHECK_EQ_I(len, 160u);
    CHECK_EQ_I(rd32(blob + 4u), 3u);
    CHECK_EQ_I(rd32(blob + 152u), 9u);
    CHECK_EQ_I(rd32(blob + 156u), LC_ST_ENABLE_PAUSED);

    lc_bus_config_t decoded;
    uint32_t ti = 0, to = 0, wi = 0, wo = 0, seq = 0, gen = 0;
    uint32_t enable = 0, source = 0;
    CHECK_EQ_I(lc_st_decode_enable(blob, len, &decoded, &ti, &to, &wi, &wo,
                                   &seq, &gen, &enable, &source), LC_ST_OK);
    CHECK_EQ_I(decoded.window_minutes, 17u);
    CHECK_EQ_I(ti, 121u);
    CHECK_EQ_I(to, 45u);
    CHECK_EQ_I(wi, 7u);
    CHECK_EQ_I(wo, 9u);
    CHECK_EQ_I(seq, 13u);
    CHECK_EQ_I(gen, 9u);
    CHECK_EQ_I(enable, LC_ST_ENABLE_PAUSED);
    CHECK_EQ_I(source, 3u);

    uint8_t bad_crc[LC_ST_BLOB_MAX];
    memcpy(bad_crc, blob, len);
    bad_crc[24] ^= 0x20u;
    CHECK_EQ_I(lc_st_decode_enable(bad_crc, len, &decoded, &ti, &to, &wi, &wo,
                                   &seq, &gen, &enable, &source), LC_ST_ERR_CRC);

    uint8_t bad_state[LC_ST_BLOB_MAX];
    memcpy(bad_state, blob, len);
    wr32(bad_state + 156u, 3u);
    wr32(bad_state + 8u, test_crc32(bad_state + 12u, len - 12u));
    CHECK_EQ_I(lc_st_decode_enable(bad_state, len, &decoded, &ti, &to, &wi, &wo,
                                   &seq, &gen, &enable, &source), LC_ST_ERR_CONTENT);

    uint8_t unknown[LC_ST_BLOB_MAX];
    memcpy(unknown, blob, len);
    wr32(unknown + 4u, 4u);
    CHECK_EQ_I(lc_st_decode_enable(unknown, len, &decoded, &ti, &to, &wi, &wo,
                                   &seq, &gen, &enable, &source), LC_ST_ERR_SCHEMA);
}

static void test_pause_and_resume_use_new_window_and_tracks(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v2_t api;
    lcstub_make_table(stub, &api);
    lcstub_set_model(stub, 1, 7u, 3u, 1u, "od-demo", "1.2");
    lcstub_set_class(stub, 0u, "person");

    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = &api;
    lcbus_t bus;
    lcbus_init(&bus, &ops);
    bus.state_schema = 3u;
    bus.enable_state = LCBUS_ENABLE_UNKNOWN;
    bus.config_generation = 1u;
    lcbus_restore(&bus);
    lcbus_rebind(&bus, 1);

    lc_bus_config_t cfg = bus.cfg;
    cfg.window_minutes = 1u;
    cfg.max_dist_permille = 1000u;
    CHECK_EQ_I(lcbus_apply_config(&bus, &cfg), 0);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_ENABLED);

    deliver_crossing(stub, &bus);
    CHECK_EQ_I(bus.total_in, 1u);
    CHECK_EQ_I(bus.window_in, 1u);
    lcstub_set_tick(stub, 60001u);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(bus.report_seq, 1u);
    CHECK_EQ_I(stub->report_count, 1u);

    for (uint32_t i = 0; i < 6u; i++) {
        lcstub_push_frame(stub, i + 1u, 50000u + i * 100u, 7u, 3u,
                          0u, 0u, NULL, 0u);
        uint8_t event[LC_APP_EVENT_BUF_CAP];
        uint32_t event_len = stub->event_len[stub->ev_head];
        memcpy(event, stub->events[stub->ev_head], event_len);
        stub->ev_head = (stub->ev_head + 1) % LCSTUB_MAX_EVENTS;
        stub->ev_count--;
        lcbus_on_event(&bus, event, event_len);
    }

    static const float second_crossing[] = { 0.30f, 0.44f, 0.58f, 0.72f };
    lcstub_set_tick(stub, 60200u);
    deliver_path(stub, &bus, second_crossing, 4u, 61000u);
    CHECK_EQ_I(bus.total_in, 2u);
    CHECK_EQ_I(bus.window_in, 1u);
    CHECK(bus.pending[0].in_use);
    uint32_t report_calls = lcstub_calls(stub, LCSTUB_FN_REPORT_SUBMIT);
    uint32_t state_calls = lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT);
    uint32_t applied_revision = 0;

    {
        CHECK_EQ_I(lcbus_enable_set(&bus, LC_ST_ENABLE_PAUSED, 99u,
                                    bus.revision, &applied_revision),
                   LCBUS_TXN_ERR_STALE_CONFIG);
        CHECK_EQ_I(lcbus_enable_set(&bus, LC_ST_ENABLE_PAUSED,
                                    bus.config_generation, bus.revision - 1u,
                                    &applied_revision),
                   LCBUS_TXN_ERR_STATE_CONFLICT);
        CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), state_calls);
        CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_ENABLED);

        CHECK_EQ_I(lcbus_enable_set(&bus, LC_ST_ENABLE_PAUSED,
                                    bus.config_generation, bus.revision,
                                    &applied_revision), LCBUS_TXN_OK);
        CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_PAUSED);
        CHECK_EQ_I(applied_revision, bus.revision);
        CHECK_EQ_I(bus.total_in, 2u);
        CHECK_EQ_I(bus.total_out, 0u);
        CHECK_EQ_I(bus.window_in, 0u);
        CHECK_EQ_I(bus.window_out, 0u);
        CHECK_EQ_I(bus.report_seq, 1u);
        CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_REPORT_SUBMIT), report_calls);
        CHECK_EQ_I(stub->report_count, 1u);
        CHECK(bus.pending[0].in_use);
        CHECK(bus.tracker == NULL);

        static const float paused_crossing[] = { 0.30f, 0.44f, 0.58f, 0.72f };
        lcstub_set_tick(stub, 90000u);
        deliver_path(stub, &bus, paused_crossing, 4u, 90000u);
        lcstub_set_tick(stub, 400000u);
        lcbus_on_idle(&bus);
        CHECK_EQ_I(bus.total_in, 2u);
        CHECK_EQ_I(bus.window_in, 0u);
        CHECK_EQ_I(bus.report_seq, 1u);
        CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_REPORT_SUBMIT), report_calls);

        lcstub_set_tick(stub, 500000u);
        CHECK_EQ_I(lcbus_enable_set(&bus, LC_ST_ENABLE_ENABLED,
                                    bus.config_generation, bus.revision,
                                    &applied_revision), LCBUS_TXN_OK);
        CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_ENABLED);
        CHECK_EQ_I(bus.window_start_ms, 500000u);
        CHECK_EQ_I(bus.window_in, 0u);
        CHECK_EQ_I(bus.report_seq, 1u);

        lcstub_det_t detection = { 0.45f, 0.30f - 0.02f,
                                   0.1f, 0.04f, 0.9f, 0u };
        lcstub_push_frame(stub, 1u, 500000u, 7u, 3u, 0u, 0u,
                          &detection, 1u);
        uint8_t event[LC_APP_EVENT_BUF_CAP];
        uint32_t event_len = stub->event_len[stub->ev_head];
        memcpy(event, stub->events[stub->ev_head], event_len);
        stub->ev_head = (stub->ev_head + 1) % LCSTUB_MAX_EVENTS;
        stub->ev_count--;
        lcbus_on_event(&bus, event, event_len);
        CHECK_EQ_I(bus.total_out, 0u);
        CHECK_EQ_I(bus.window_out, 0u);
        CHECK(bus.tracker != NULL);
    }

    lcstub_destroy(stub);
}

static void start_empty_v4(lcstub_t *stub, lc_app_api_v2_t *api, lcbus_t *bus)
{
    lcstub_make_table(stub, api);
    lcstub_set_model(stub, 1, 7u, 3u, 1u, "od-demo", "1.2");
    lcstub_set_class(stub, 0u, "person");
    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = api;
    lcbus_init(bus, &ops);
    bus->state_schema = 3u;
    bus->enable_state = LCBUS_ENABLE_UNKNOWN;
    bus->config_generation = 1u;
    lcbus_restore(bus);
    lcbus_rebind(bus, 1);
}

static void test_enable_commit_failures_restrict_business_state(void)
{
    lcstub_t *io_stub = lcstub_new();
    lc_app_api_v2_t io_api;
    lcbus_t io_bus;
    start_empty_v4(io_stub, &io_api, &io_bus);
    uint32_t revision = 0;
    lcstub_state_commit_fault(io_stub, LC_RET_IO_ERROR, 1);
    CHECK_EQ_I(lcbus_enable_set(&io_bus, LC_ST_ENABLE_PAUSED,
                                io_bus.config_generation, io_bus.revision,
                                &revision), LCBUS_TXN_ERR_STORAGE_IO);
    CHECK_EQ_I(io_bus.enable_state, LCBUS_ENABLE_UNKNOWN);
    CHECK(lcbus_storage_restricted(&io_bus));
    deliver_crossing(io_stub, &io_bus);
    CHECK_EQ_I(io_bus.total_in, 0u);
    CHECK_EQ_I(io_stub->report_count, 0u);
    lcstub_destroy(io_stub);

    lcstub_t *read_stub = lcstub_new();
    lc_app_api_v2_t read_api;
    lcbus_t read_bus;
    start_empty_v4(read_stub, &read_api, &read_bus);
    uint32_t read_revision = read_bus.revision;
    lcstub_state_read_fault(read_stub, LC_RET_IO_ERROR, 1);
    CHECK_EQ_I(lcbus_enable_set(&read_bus, LC_ST_ENABLE_PAUSED,
                                read_bus.config_generation, read_bus.revision,
                                &revision), LCBUS_TXN_ERR_STORAGE_UNKNOWN);
    CHECK_EQ_I(read_bus.enable_state, LCBUS_ENABLE_UNKNOWN);
    CHECK(lcbus_storage_restricted(&read_bus));
    CHECK_EQ_I(read_stub->state_revision, read_revision + 1u);
    deliver_crossing(read_stub, &read_bus);
    CHECK_EQ_I(read_bus.total_in, 0u);
    CHECK_EQ_I(read_stub->report_count, 0u);
    lcstub_destroy(read_stub);

    lcstub_t *torn_stub = lcstub_new();
    lc_app_api_v2_t torn_api;
    lcbus_t torn_bus;
    start_empty_v4(torn_stub, &torn_api, &torn_bus);
    torn_stub->state_torn_write = 1;
    CHECK_EQ_I(lcbus_enable_set(&torn_bus, LC_ST_ENABLE_PAUSED,
                                torn_bus.config_generation, torn_bus.revision,
                                &revision), LCBUS_TXN_ERR_STORAGE_UNKNOWN);
    CHECK_EQ_I(torn_bus.enable_state, LCBUS_ENABLE_UNKNOWN);
    CHECK(lcbus_storage_restricted(&torn_bus));
    CHECK_EQ_I(lc_st_decode_enable(torn_stub->state_blob, torn_stub->state_len,
                                   &torn_bus.cfg, &torn_bus.total_in,
                                   &torn_bus.total_out, &torn_bus.window_in,
                                   &torn_bus.window_out, &torn_bus.report_seq,
                                   &torn_bus.config_generation, &revision,
                                   &read_revision), LC_ST_ERR_CRC);
    lcstub_destroy(torn_stub);

    lcstub_t *conflict_stub = lcstub_new();
    lc_app_api_v2_t conflict_api;
    lcbus_t conflict_bus;
    start_empty_v4(conflict_stub, &conflict_api, &conflict_bus);
    conflict_stub->state_revision++;
    CHECK_EQ_I(lcbus_enable_set(&conflict_bus, LC_ST_ENABLE_PAUSED,
                                conflict_bus.config_generation,
                                conflict_bus.revision, &revision),
               LCBUS_TXN_ERR_STATE_CONFLICT);
    CHECK_EQ_I(conflict_bus.enable_state, LCBUS_ENABLE_UNKNOWN);
    CHECK(lcbus_storage_restricted(&conflict_bus));
    lcstub_destroy(conflict_stub);
}

static uint32_t make_v4_command(uint8_t *out, uint32_t type,
                                uint32_t session, uint32_t request,
                                uint32_t config_generation, uint32_t flags,
                                const uint8_t *payload, uint32_t payload_len)
{
    uint32_t len = LC_CTRL_HEADER_SIZE + payload_len;
    memset(out, 0, len);
    wr32(out + 0u, LC_CTRL_V4_PROTO_MAGIC);
    out[4] = 1u;
    out[6] = (uint8_t)type;
    out[7] = (uint8_t)(type >> 8);
    wr32(out + 8u, len);
    wr32(out + 12u, session);
    wr32(out + 16u, request);
    wr32(out + 20u, config_generation);
    wr32(out + 28u, flags);
    if (payload_len) memcpy(out + LC_CTRL_HEADER_SIZE, payload, payload_len);
    return len;
}

static int bytes_contain(const uint8_t *data, uint32_t len,
                         const char *needle, uint32_t needle_len)
{
    if (needle_len > len) return 0;
    for (uint32_t i = 0; i <= len - needle_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) return 1;
    }
    return 0;
}

static uint32_t make_enable_command(uint8_t *out, uint32_t session,
                                    uint32_t request, uint32_t config_generation,
                                    uint32_t desired, uint32_t expected_revision)
{
    uint8_t payload[16] = { 0x45u, 0x4Eu, 0x42u, 0x31u };
    wr32(payload + 4u, desired);
    wr32(payload + 8u, expected_revision);
    return make_v4_command(out, LC_CTRL_V4_TYPE_ENABLE_SET, session, request,
                           config_generation, 0u, payload, sizeof(payload));
}

static void start_v4_control(lcstub_t *stub, lc_app_api_v4_t *api,
                             lcbus_t *bus, lc_ctrl_t *ctrl)
{
    lcstub_make_table_v4(stub, api);
    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = api;
    lcbus_init(bus, &ops);
    bus->state_schema = LC_ST_BLOB_SCHEMA_ENABLE;
    bus->enable_state = LCBUS_ENABLE_UNKNOWN;
    bus->config_generation = 1u;
    lcbus_restore(bus);
    lc_ctrl_init_v4(ctrl, bus, api);
}

static void test_v4_enable_receipt_dedup_and_snapshot(void)
{
    static const uint8_t golden_command[48] = {
        0x4eu,0x46u,0x43u,0x34u,0x01u,0x00u,0x05u,0x00u,
        0x30u,0x00u,0x00u,0x00u,0x4du,0x00u,0x00u,0x00u,
        0x7bu,0x00u,0x00u,0x00u,0x01u,0x00u,0x00u,0x00u,
        0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,
        0x45u,0x4eu,0x42u,0x31u,0x02u,0x00u,0x00u,0x00u,
        0x01u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u
    };
    static const uint8_t golden_receipt[48] = {
        0x4eu,0x46u,0x43u,0x34u,0x01u,0x00u,0x03u,0x00u,
        0x30u,0x00u,0x00u,0x00u,0x4du,0x00u,0x00u,0x00u,
        0x7bu,0x00u,0x00u,0x00u,0x01u,0x00u,0x00u,0x00u,
        0x02u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,
        0x45u,0x4eu,0x52u,0x31u,0x02u,0x00u,0x00u,0x00u,
        0x02u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u
    };
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcbus_t bus;
    lc_ctrl_t ctrl;
    start_v4_control(stub, &api, &bus, &ctrl);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_ENABLED);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = make_enable_command(cmd, 77u, 123u, bus.config_generation,
                                      LC_ST_ENABLE_PAUSED, bus.revision);
    CHECK_EQ_I(len, sizeof(golden_command));
    CHECK(memcmp(cmd, golden_command, sizeof(golden_command)) == 0);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_PAUSED);
    CHECK_EQ_I(lcstub_reply_count(stub), 1);
    CHECK_EQ_I(stub->replies[0].len, LC_CTRL_V4_ENABLE_RECEIPT_SIZE);
    const uint8_t *receipt = lcstub_reply(stub, 0);
    CHECK_EQ_I(rd32(receipt), LC_CTRL_V4_PROTO_MAGIC);
    CHECK_EQ_I(rd32(receipt + 8u), LC_CTRL_V4_ENABLE_RECEIPT_SIZE);
    CHECK_EQ_I(rd32(receipt + 12u), 77u);
    CHECK_EQ_I(rd32(receipt + 16u), 123u);
    CHECK_EQ_I(rd32(receipt + 20u), bus.config_generation);
    CHECK_EQ_I(rd32(receipt + 24u), bus.revision);
    CHECK_EQ_I(rd32(receipt + 28u), LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(rd32(receipt + 32u), LC_CTRL_V4_RECEIPT_MAGIC);
    CHECK_EQ_I(rd32(receipt + 36u), LC_ST_ENABLE_PAUSED);
    CHECK_EQ_I(rd32(receipt + 40u), bus.revision);
    CHECK_EQ_I(rd32(receipt + 44u), 0u);
    CHECK(memcmp(receipt, golden_receipt, sizeof(golden_receipt)) == 0);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 2u);
    CHECK_EQ_I(lcstub_snapshot_count(stub), 1);
    uint32_t snapshot_len = 0u;
    const uint8_t *snapshot = lcstub_snapshot(stub, 0, &snapshot_len);
    CHECK(snapshot != NULL);
    CHECK_EQ_I(rd32(snapshot), LC_CTRL_V4_PROTO_MAGIC);
    CHECK_EQ_I(rd32(snapshot + 24u), bus.revision);
    CHECK(bytes_contain(snapshot + LC_CTRL_HEADER_SIZE,
                        snapshot_len - LC_CTRL_HEADER_SIZE,
                        "\"enable_state\":\"paused\"",
                        (uint32_t)sizeof("\"enable_state\":\"paused\"") - 1u));

    lcstub_set_tick(stub, 5000u);
    lcstub_det_t detection = { 0.45f, 0.28f, 0.1f, 0.04f, 0.9f, 0u };
    lcstub_push_frame(stub, 1u, 5000u, 7u, 3u, 0u, 0u, &detection, 1u);
    uint8_t event[LC_APP_EVENT_BUF_CAP];
    uint32_t event_len = 0u;
    CHECK_EQ_I(api.event_next(event, sizeof(event), &event_len, 0u), LC_RET_OK);
    lcbus_on_event(&bus, event, event_len);
    CHECK_EQ_I(bus.last_frame_received_valid, 1u);
    CHECK_EQ_I(bus.last_frame_received_ms, 5000u);
    CHECK_EQ_I(bus.total_in, 0u);
    CHECK_EQ_I(bus.window_in, 0u);
    lc_ctrl_snapshot_force(&ctrl);
    lc_ctrl_poll(&ctrl);
    snapshot = lcstub_snapshot(stub, 1, &snapshot_len);
    CHECK(snapshot != NULL);
    CHECK(bytes_contain(snapshot + LC_CTRL_HEADER_SIZE,
                        snapshot_len - LC_CTRL_HEADER_SIZE,
                        "\"age_ms\":0", 10u));
    CHECK(bytes_contain(snapshot + LC_CTRL_HEADER_SIZE,
                        snapshot_len - LC_CTRL_HEADER_SIZE,
                        "\"live_freshness\":\"not_connected\"",
                        (uint32_t)sizeof("\"live_freshness\":\"not_connected\"") - 1u));

    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.revision, 2u);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 2u);
    CHECK_EQ_I(lcstub_reply_count(stub), 2);
    CHECK_EQ_I(ctrl.st.dedup_cached, 1u);
    CHECK(memcmp(lcstub_reply(stub, 0), lcstub_reply(stub, 1),
                 LC_CTRL_V4_ENABLE_RECEIPT_SIZE) == 0);

    len = make_enable_command(cmd, 77u, 123u, bus.config_generation,
                              LC_ST_ENABLE_ENABLED, bus.revision);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_PAUSED);
    CHECK_EQ_I(bus.revision, 2u);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 2u);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 2) + 28u), LC_CTRL_RESULT_REJECTED_INVALID);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 2) + 36u), LC_ST_ENABLE_PAUSED);
    CHECK_EQ_I(ctrl.st.dedup_conflict, 1u);
    lcstub_destroy(stub);
}

static void test_v4_wire_rejections_and_stale_fences(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcbus_t bus;
    lc_ctrl_t ctrl;
    start_v4_control(stub, &api, &bus, &ctrl);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = make_enable_command(cmd, 22u, 1u, bus.config_generation,
                                       LC_ST_ENABLE_PAUSED, bus.revision);
    uint32_t commits = lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT);
    uint32_t replies = (uint32_t)lcstub_reply_count(stub);
    uint8_t bad[LC_CTRL_V4_ENABLE_SET_SIZE];
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad, LC_CTRL_PROTO_MAGIC);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad + 8u, sizeof(bad) - 1u);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad + 32u, 0x30424E45u);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad + 28u, 1u);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad + 44u, 1u);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad + 36u, 3u);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    memcpy(bad, cmd, sizeof(bad));
    wr32(bad + 24u, 1u);
    lcstub_push_command(stub, bad, sizeof(bad));
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(ctrl.st.wire_rejected, 7u);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), commits);
    CHECK_EQ_I(lcstub_reply_count(stub), replies);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_ENABLED);

    len = make_enable_command(cmd, 22u, 2u, bus.config_generation + 1u,
                              LC_ST_ENABLE_PAUSED, bus.revision);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 28u),
               LC_CTRL_RESULT_REJECTED_STALE_CONFIG);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 36u), LC_ST_ENABLE_ENABLED);
    len = make_enable_command(cmd, 22u, 3u, bus.config_generation,
                              LC_ST_ENABLE_PAUSED, bus.revision + 1u);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 1) + 28u),
               LC_CTRL_RESULT_FAILED_STATE_CONFLICT);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_ENABLED);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), commits);
    lcstub_destroy(stub);
}

static void test_v4_failed_commit_receipts_are_unknown(void)
{
    const int32_t faults[] = { LC_RET_IO_ERROR, LC_RET_STORAGE_UNKNOWN, LC_RET_OK };
    const uint32_t statuses[] = { LC_CTRL_RESULT_FAILED_STORAGE_IO,
                                  LC_CTRL_RESULT_FAILED_STORAGE_UNKNOWN,
                                  LC_CTRL_RESULT_FAILED_STORAGE_UNKNOWN };
    for (uint32_t i = 0; i < 3u; i++) {
        lcstub_t *stub = lcstub_new();
        lc_app_api_v4_t api;
        lcbus_t bus;
        lc_ctrl_t ctrl;
        start_v4_control(stub, &api, &bus, &ctrl);
        uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
        uint32_t len = make_enable_command(cmd, 45u, 300u + i,
                                           bus.config_generation,
                                           LC_ST_ENABLE_PAUSED, bus.revision);
        if (i < 2u) lcstub_state_commit_fault(stub, faults[i], 1);
        else stub->state_revision_reply = 99u;
        lcstub_push_command(stub, cmd, len);
        lc_ctrl_poll(&ctrl);
        CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 28u), statuses[i]);
        CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 36u),
                   LC_CTRL_V4_ENABLE_UNKNOWN);
        CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 24u), 1u);
        CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 40u), 1u);
        CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_UNKNOWN);
        CHECK(lcbus_storage_restricted(&bus));
        lcstub_destroy(stub);
    }
}

static void test_v4_lost_receipt_retry_and_session_fence(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcbus_t bus;
    lc_ctrl_t ctrl;
    start_v4_control(stub, &api, &bus, &ctrl);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = make_enable_command(cmd, 88u, 401u, bus.config_generation,
                                       LC_ST_ENABLE_PAUSED, bus.revision);
    lcstub_fault(stub, LCSTUB_FN_CONTROL_REPLY, LC_RET_IO_ERROR, 1);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(lcstub_reply_count(stub), 0);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_PAUSED);
    CHECK_EQ_I(bus.revision, 2u);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(lcstub_reply_count(stub), 1);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 2u);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 28u), LC_CTRL_RESULT_APPLIED);

    len = make_enable_command(cmd, 89u, 402u, bus.config_generation,
                              LC_ST_ENABLE_ENABLED, bus.revision);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_PAUSED);
    CHECK_EQ_I(bus.revision, 2u);
    CHECK_EQ_I(bus.session_fatal, 1u);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 2u);
    lcstub_destroy(stub);
}

static void test_v4_config_reset_and_enable_share_revision(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcbus_t bus;
    lc_ctrl_t ctrl;
    start_v4_control(stub, &api, &bus, &ctrl);
    lc_bus_config_t cfg = bus.cfg;
    cfg.window_minutes = 17u;
    uint8_t payload[LC_CFG_CAND_SIZE];
    CHECK_EQ_I(lc_cfg_encode(payload, sizeof(payload), &cfg), LC_CFG_CAND_SIZE);
    uint8_t cmd[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = make_v4_command(cmd, LC_CTRL_TYPE_CONFIG_APPLY, 62u, 500u,
                                   bus.config_generation, 0u,
                                   payload, sizeof(payload));
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.config_generation, 2u);
    CHECK_EQ_I(bus.revision, 2u);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 0) + 28u), LC_CTRL_RESULT_APPLIED);

    len = make_v4_command(cmd, LC_CTRL_TYPE_COUNTERS_RESET, 62u, 501u,
                          bus.config_generation, LC_CTRL_FLAG_DESTRUCTIVE_CONFIRMED,
                          NULL, 0u);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.revision, 3u);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 1) + 28u), LC_CTRL_RESULT_APPLIED);

    len = make_enable_command(cmd, 62u, 502u, bus.config_generation,
                              LC_ST_ENABLE_PAUSED, bus.revision);
    lcstub_push_command(stub, cmd, len);
    lc_ctrl_poll(&ctrl);
    CHECK_EQ_I(bus.revision, 4u);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_PAUSED);
    CHECK_EQ_I(rd32(lcstub_reply(stub, 2) + 28u), LC_CTRL_RESULT_APPLIED);
    CHECK_EQ_I(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT), 4u);
    lcstub_destroy(stub);
}

int main(void)
{
    test_v3_corrupt_paused_state_blocks_frame_and_idle();
    test_v4_paused_schema3_restores_and_blocks_frame();
    test_legacy_migration_commits_once(1u);
    test_legacy_migration_commits_once(2u);
    test_schema3_codec_and_failures();
    test_pause_and_resume_use_new_window_and_tracks();
    test_enable_commit_failures_restrict_business_state();
    test_v4_enable_receipt_dedup_and_snapshot();
    test_v4_wire_rejections_and_stale_fences();
    test_v4_failed_commit_receipts_are_unknown();
    test_v4_lost_receipt_retry_and_session_fence();
    test_v4_config_reset_and_enable_share_revision();
    TEST_REPORT("line-crossing-enable");
}
