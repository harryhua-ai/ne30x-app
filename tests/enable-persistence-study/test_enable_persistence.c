#include <stdio.h>
#include <string.h>

#include "host_stub.h"
#include "lc_app_entry_v3.h"
#include "lc_bus.h"
#include "lc_ctrl.h"
#include "lc_stateblob.h"
#include "study_model.h"

static int failures;
static int checks;
static lcstub_t *stub;
static lc_app_api_v3_t api;
static lcbus_t bus;
static lc_ctrl_t ctrl;

static void check(int condition, const char *name)
{
    checks++;
    if (!condition) {
        failures++;
        printf("FAIL %s\n", name);
    }
}

static uint32_t make_schema1(uint8_t *blob, uint32_t total_in,
                             uint32_t total_out, uint32_t window_in,
                             uint32_t window_out, uint32_t report_seq)
{
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    return lc_st_encode(blob, LC_ST_BLOB_MAX, &cfg, total_in, total_out,
                        window_in, window_out, report_seq);
}

static uint32_t make_schema2(uint8_t *blob, uint32_t total_in,
                             uint32_t total_out, uint32_t window_in,
                             uint32_t window_out, uint32_t report_seq,
                             uint32_t generation)
{
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    return lc_st_encode_gen(blob, LC_ST_BLOB_MAX, &cfg, total_in, total_out,
                            window_in, window_out, report_seq, generation);
}

static void setup_app(const uint8_t *blob, uint32_t len, uint32_t revision)
{
    stub = lcstub_new();
    lcstub_set_model(stub, 1, 7, 3, 2, "od-demo", "1.2");
    lcstub_set_class(stub, 0, "person");
    lcstub_set_class(stub, 1, "car");
    if (blob != NULL) lcstub_set_state(stub, blob, len, revision);
    lcstub_make_table_v3(stub, &api);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &api;
    lcbus_init(&bus, &ops);
    bus.state_schema = 2u;
    bus.config_generation = 1u;
    lcbus_restore(&bus);
    lc_ctrl_init(&ctrl, &bus, &api);
    lcbus_rebind(&bus, 1);
}

static void teardown_app(void)
{
    lcstub_destroy(stub);
    stub = NULL;
}

static void feed_crossing(int down, uint32_t sequence, uint32_t tick)
{
    static const float ys_down[4] = { 0.30f, 0.44f, 0.58f, 0.72f };
    static const float ys_up[4] = { 0.72f, 0.58f, 0.44f, 0.30f };
    const float *ys = down ? ys_down : ys_up;
    for (int i = 0; i < 4; i++) {
        lcstub_det_t detection = { 0.45f, ys[i] - 0.02f, 0.10f, 0.04f, 0.9f, 0 };
        uint8_t event[LC_APP_EVENT_BUF_CAP];
        uint32_t len = 0u;
        lcstub_push_frame(stub, sequence + (uint32_t)i, tick + (uint32_t)i * 100u,
                          7u, 3u, 0u, 0u, &detection, 1u);
        check(api.event_next(event, sizeof(event), &len, 0u) == LC_RET_OK,
              "fixture delivered frame");
        lcbus_on_event(&bus, event, len);
    }
}

static void test_schema_codec_and_crc(void)
{
    uint8_t schema1[LC_ST_BLOB_MAX];
    uint8_t schema2[LC_ST_BLOB_MAX];
    uint32_t n1 = make_schema1(schema1, 11u, 22u, 3u, 4u, 5u);
    uint32_t n2 = make_schema2(schema2, 31u, 42u, 6u, 7u, 8u, 9u);
    lc_bus_config_t cfg;
    uint32_t ti, to, wi, wo, seq, gen;
    check(n1 == 152u, "schema1 is 152 bytes");
    check(n2 == 160u, "schema2 is 160 bytes");
    check(lc_st_decode(schema1, n1, &cfg, &ti, &to, &wi, &wo, &seq) == LC_ST_OK,
          "schema1 CRC and content pass");
    check(ti == 11u && to == 22u && wi == 3u && wo == 4u && seq == 5u,
          "schema1 counters decode");
    check(lc_st_decode_gen(schema2, n2, &cfg, &ti, &to, &wi, &wo, &seq, &gen) == LC_ST_OK,
          "schema2 CRC and content pass");
    check(ti == 31u && to == 42u && wi == 6u && wo == 7u && seq == 8u && gen == 9u,
          "schema2 counters and generation decode");
    schema1[24] ^= 0x20u;
    schema2[24] ^= 0x20u;
    check(lc_st_decode(schema1, n1, &cfg, &ti, &to, &wi, &wo, &seq) == LC_ST_ERR_CRC,
          "schema1 bad CRC rejected");
    check(lc_st_decode_gen(schema2, n2, &cfg, &ti, &to, &wi, &wo, &seq, &gen) == LC_ST_ERR_CRC,
          "schema2 bad CRC rejected");
}

static void test_real_migration_and_repeat_start(void)
{
    uint8_t legacy[LC_ST_BLOB_MAX];
    uint32_t len = make_schema1(legacy, 121u, 45u, 7u, 9u, 13u);
    setup_app(legacy, len, 4u);
    check(bus.persist_state == LCBUS_PERSIST_OK, "schema1 restore status OK");
    check(bus.total_in == 121u && bus.total_out == 45u &&
          bus.window_in == 7u && bus.window_out == 9u && bus.report_seq == 13u,
          "schema1 restore preserves all counters and sequence");
    check(bus.config_generation == 1u && bus.state_dirty,
          "schema1 upgrade marks one generation initialization");
    lcbus_flush(&bus, 1);
    check(stub->state_len == 160u && stub->state_revision == 5u,
          "real lcbus flush commits schema2 with CAS revision");
    lc_bus_config_t cfg;
    uint32_t ti, to, wi, wo, seq, gen;
    check(lc_st_decode_gen(stub->state_blob, stub->state_len, &cfg,
                           &ti, &to, &wi, &wo, &seq, &gen) == LC_ST_OK,
          "committed schema2 blob validates");
    check(ti == 121u && to == 45u && wi == 7u && wo == 9u && seq == 13u && gen == 1u,
          "real migration did not drop counters");
    uint32_t commit_calls = lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT);
    lcbus_t second;
    lc_app_api_v3_t second_api;
    lcstub_make_table_v3(stub, &second_api);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v3();
    ops.user = &second_api;
    lcbus_init(&second, &ops);
    second.state_schema = 2u;
    second.config_generation = 1u;
    lcbus_restore(&second);
    check(second.persist_state == LCBUS_PERSIST_OK && !second.state_dirty,
          "repeated startup restores migrated state without a write");
    check(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT) == commit_calls,
          "repeat startup preserves storage revision");
    teardown_app();
}

static void test_real_corrupt_and_unknown_storage(void)
{
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len = make_schema2(blob, 8u, 9u, 2u, 3u, 4u, 1u);
    blob[24] ^= 1u;
    setup_app(blob, len, 7u);
    uint8_t before[LC_ST_BLOB_MAX];
    memcpy(before, stub->state_blob, stub->state_len);
    uint32_t commits = lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT);
    check(bus.persist_state == LCBUS_PERSIST_CORRUPT, "bad state is CORRUPT");
    lcbus_flush(&bus, 1);
    check(stub->state_len == len && memcmp(before, stub->state_blob, len) == 0,
          "corrupt bytes are not overwritten by flush");
    check(lcstub_calls(stub, LCSTUB_FN_STATE_COMMIT) == commits,
          "corrupt restore does not write a default state");
    teardown_app();

    setup_app(NULL, 0u, 0u);
    lcstub_state_read_fault(stub, LC_RET_STORAGE_UNKNOWN, 2);
    lcbus_restore(&bus);
    check(bus.persist_state == LCBUS_PERSIST_DEGRADED &&
          lcbus_storage_restricted(&bus), "read failure enters restricted storage state");
    lcbus_flush(&bus, 1);
    check(!stub->state_present && lcbus_storage_restricted(&bus),
          "unknown read does not invent an empty committed state");
    teardown_app();
}

static void test_real_commit_faults_and_cas_conflict(void)
{
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len = make_schema2(blob, 40u, 50u, 2u, 3u, 7u, 2u);
    setup_app(blob, len, 5u);
    uint8_t before[LC_ST_BLOB_MAX];
    memcpy(before, stub->state_blob, len);
    bus.total_in = 41u;
    bus.state_dirty = 1u;
    bus.business_mutated = 1u;
    lcstub_state_commit_fault(stub, LC_RET_IO_ERROR, 1);
    lcbus_flush(&bus, 1);
    check(bus.persist_state == LCBUS_PERSIST_DEGRADED &&
          memcmp(before, stub->state_blob, len) == 0,
          "real IO failure keeps old bytes and marks degraded");
    teardown_app();

    setup_app(blob, len, 5u);
    memcpy(before, stub->state_blob, len);
    bus.total_in = 41u;
    bus.state_dirty = 1u;
    bus.business_mutated = 1u;
    lcstub_state_commit_fault(stub, LC_RET_STORAGE_UNKNOWN, 1);
    lcbus_flush(&bus, 1);
    check(bus.storage_unknown_latch && lcbus_storage_restricted(&bus),
          "real STORAGE_UNKNOWN latches restrictions");
    lcbus_flush(&bus, 1);
    check(memcmp(before, stub->state_blob, len) == 0 &&
          bus.persist_state == LCBUS_PERSIST_CONFLICT,
          "unknown readback conflict leaves stored bytes authoritative");
    teardown_app();

    setup_app(blob, len, 5u);
    uint8_t external[LC_ST_BLOB_MAX];
    uint32_t external_len = make_schema2(external, 99u, 50u, 2u, 3u, 7u, 2u);
    lcstub_set_state(stub, external, external_len, 6u);
    bus.total_in = 41u;
    bus.state_dirty = 1u;
    bus.business_mutated = 1u;
    lcbus_flush(&bus, 1);
    check(bus.persist_state == LCBUS_PERSIST_CONFLICT &&
          lc_rd_u32(stub->state_blob + 132) == 99u,
          "real CAS conflict preserves newer authoritative blob");
    teardown_app();
}

static void test_real_frame_and_idle_report_paths(void)
{
    setup_app(NULL, 0u, 0u);
    bus.cfg.window_minutes = 1u;
    bus.window_start_ms = 0u;
    lcstub_set_tick(stub, 60000u);
    lcstub_push_frame(stub, 1u, 60000u, 7u, 3u, 0u, 0u, NULL, 0u);
    uint8_t event[LC_APP_EVENT_BUF_CAP];
    uint32_t len = 0u;
    check(api.event_next(event, sizeof(event), &len, 0u) == LC_RET_OK,
          "frame fixture available");
    lcbus_on_event(&bus, event, len);
    check(bus.report_seq == 1u && stub->report_count == 1,
          "real FRAME path closes and submits expired window");
    teardown_app();

    setup_app(NULL, 0u, 0u);
    bus.cfg.window_minutes = 1u;
    bus.window_start_ms = 0u;
    lcstub_set_tick(stub, 60000u);
    lcbus_on_idle(&bus);
    check(bus.report_seq == 1u && stub->report_count == 1,
          "real idle path closes and submits expired window");
    teardown_app();
}

static void test_candidate_pause_resume_and_both_gates(void)
{
    uint8_t legacy[LC_ST_BLOB_MAX];
    uint32_t len = make_schema2(legacy, 100u, 80u, 5u, 6u, 17u, 3u);
    study_store_t store;
    study_store_seed(&store, legacy, len, 8u);
    study_runtime_t runtime = { 0 };
    check(study_restore(&store, &runtime) == STUDY_RESULT_APPLIED &&
          runtime.record.enable == STUDY_ENABLE_ENABLED,
          "valid old schema maps to Enabled on first migration");
    check(study_migrate(&store, &runtime) == STUDY_RESULT_APPLIED &&
          runtime.revision == 9u,
          "candidate schema3 migration commits with CAS");
    check(study_migrate(&store, &runtime) == STUDY_RESULT_ALREADY &&
          store.revision == 9u,
          "candidate repeated migration is idempotent");
    runtime.report_queue_count = 2u;
    runtime.tracker_active = 1;
    check(study_set_enable(&store, &runtime, STUDY_ENABLE_PAUSED, 9u,
                           44u, 44u, 120000u) == STUDY_RESULT_APPLIED,
          "candidate pause becomes applied only after store commit");
    check(runtime.record.enable == STUDY_ENABLE_PAUSED && !runtime.tracker_active &&
          runtime.record.window_in == 0u && runtime.record.window_out == 0u &&
          runtime.record.total_in == 100u && runtime.record.total_out == 80u &&
          runtime.record.report_seq == 17u && runtime.report_queue_count == 2u,
          "pause clears window and tracker while preserving totals sequence and queue");
    study_runtime_t restarted = { 0 };
    restarted.report_queue_count = runtime.report_queue_count;
    check(study_restore(&store, &restarted) == STUDY_RESULT_APPLIED &&
          restarted.record.enable == STUDY_ENABLE_PAUSED &&
          restarted.record.total_in == 100u && restarted.record.report_seq == 17u,
          "restart reads committed Paused and historical totals");

    setup_app(NULL, 0u, 0u);
    bus.total_in = restarted.record.total_in;
    bus.total_out = restarted.record.total_out;
    bus.report_seq = restarted.record.report_seq;
    bus.window_in = restarted.record.window_in;
    bus.window_out = restarted.record.window_out;
    bus.window_start_ms = 0u;
    bus.cfg.window_minutes = 1u;
    lcstub_set_tick(stub, 60000u);
    api.report_submit("{}", 2u, 1u, &bus.host_boot_id);
    api.report_submit("{}", 2u, 2u, &bus.host_boot_id);
    bus.pending[0].in_use = 1u;
    bus.pending[0].seq = 17u;
    uint32_t report_before = bus.report_seq;
    uint32_t totals_before = bus.total_in;
    uint32_t queue_before = (uint32_t)stub->report_count;
    for (int i = 0; i < 4; i++) {
        lcstub_det_t detection = { 0.45f, 0.28f + 0.14f * (float)i,
                                   0.10f, 0.04f, 0.9f, 0 };
        uint8_t event[LC_APP_EVENT_BUF_CAP];
        uint32_t event_len = 0u;
        lcstub_push_frame(stub, (uint32_t)i + 1u, 61000u + (uint32_t)i * 100u,
                          7u, 3u, 0u, 0u, &detection, 1u);
        check(api.event_next(event, sizeof(event), &event_len, 0u) == LC_RET_OK,
              "paused frame fixture delivered");
        check(study_dispatch_frame(&restarted, &bus, event, event_len) == 0,
              "paused FRAME entry is gated");
    }
    check(study_dispatch_idle(&restarted, &bus) == 0,
          "paused idle entry is gated");
    check(bus.total_in == totals_before && bus.report_seq == report_before &&
          bus.window_in == 0u && bus.window_out == 0u,
          "paused frame and idle add no crossing or partial-window sequence");
    check(stub->report_count == (int)queue_before && bus.pending[0].in_use,
          "pause preserves queued and pending historical reports");
    teardown_app();

    check(study_set_enable(&store, &restarted, STUDY_ENABLE_ENABLED, 10u,
                           45u, 45u, 240000u) == STUDY_RESULT_APPLIED,
          "resume commits through a fresh session and revision");
    check(restarted.record.enable == STUDY_ENABLE_ENABLED &&
          restarted.window_start_ms == 240000u && !restarted.tracker_active &&
          restarted.record.window_in == 0u && restarted.record.window_out == 0u &&
          restarted.record.total_in == 100u && restarted.record.total_out == 80u &&
          restarted.record.report_seq == 17u && restarted.report_queue_count == 2u,
          "resume opens a fresh window and preserves accumulated history");
}

static void test_candidate_crash_unknown_conflict_and_reinstall(void)
{
    uint8_t legacy[LC_ST_BLOB_MAX];
    uint32_t len = make_schema1(legacy, 20u, 30u, 4u, 5u, 12u);
    study_store_t store;
    study_store_seed(&store, legacy, len, 3u);
    study_runtime_t runtime = { 0 };
    study_restore(&store, &runtime);
    store.next_fault = STUDY_FAULT_IO_BEFORE_WRITE;
    check(study_set_enable(&store, &runtime, STUDY_ENABLE_PAUSED, 3u,
                           8u, 8u, 70000u) == STUDY_RESULT_FAILED_IO,
          "pre-commit IO failure is not acknowledged as Paused");
    study_runtime_t before_commit_restart = { 0 };
    study_restore(&store, &before_commit_restart);
    check(before_commit_restart.record.enable == STUDY_ENABLE_ENABLED &&
          before_commit_restart.record.total_in == 20u,
          "crash before commit retains valid old state as Enabled");

    store.next_fault = STUDY_FAULT_UNKNOWN_AFTER_WRITE;
    check(study_set_enable(&store, &runtime, STUDY_ENABLE_PAUSED, 3u,
                           8u, 8u, 70000u) == STUDY_RESULT_UNKNOWN && runtime.restricted,
          "lost commit receipt returns UNKNOWN without optimistic state");
    study_runtime_t after_commit_restart = { 0 };
    study_restore(&store, &after_commit_restart);
    check(after_commit_restart.record.enable == STUDY_ENABLE_PAUSED &&
          after_commit_restart.record.total_in == 20u &&
          after_commit_restart.record.report_seq == 12u,
          "crash after commit before receipt recovers persisted Paused");

    uint8_t corrupt[LC_ST_BLOB_MAX];
    memcpy(corrupt, store.blob, store.len);
    corrupt[24] ^= 1u;
    study_store_t corrupt_store;
    study_store_seed(&corrupt_store, corrupt, store.len, store.revision);
    study_runtime_t corrupt_runtime = { 0 };
    check(study_restore(&corrupt_store, &corrupt_runtime) == STUDY_RESULT_UNKNOWN &&
          corrupt_runtime.restricted &&
          corrupt_runtime.record.enable == STUDY_ENABLE_UNKNOWN,
          "corrupt confirmed schema3 never defaults to Enabled");

    store.next_fault = STUDY_FAULT_TORN_WRITE;
    check(study_set_enable(&store, &after_commit_restart, STUDY_ENABLE_ENABLED,
                           4u, 9u, 9u, 90000u) == STUDY_RESULT_UNKNOWN,
          "torn candidate write surfaces STORAGE_UNKNOWN");
    study_runtime_t torn_restart = { 0 };
    check(study_restore(&store, &torn_restart) == STUDY_RESULT_UNKNOWN &&
          torn_restart.restricted,
          "torn candidate blob stays restricted on restart");

    study_runtime_t unauthorized = { 0 };
    study_store_t clean;
    study_store_seed(&clean, legacy, len, 3u);
    study_restore(&clean, &unauthorized);
    check(study_set_enable(&clean, &unauthorized, STUDY_ENABLE_PAUSED, 3u,
                           10u, 11u, 90000u) == STUDY_RESULT_UNAUTHORIZED,
          "request from a stale session is rejected");
    check(study_set_enable(&clean, &unauthorized, STUDY_ENABLE_PAUSED, 2u,
                           11u, 11u, 90000u) == STUDY_RESULT_CONFLICT,
          "stale state revision cannot replay a control request");

    study_store_seed(&clean, store.blob, store.len, store.revision);
    study_runtime_t downgrade = { 0 };
    study_restore(&clean, &downgrade);
    uint8_t stale_major[LC_ST_BLOB_MAX];
    uint32_t stale_len = make_schema2(stale_major, 22u, 33u, 0u, 0u, 13u, 1u);
    study_store_seed(&clean, stale_major, stale_len, 7u);
    study_runtime_t reinstalled = { 0 };
    study_store_clear(&clean);
    study_restore(&clean, &reinstalled);
    check(reinstalled.record.enable == STUDY_ENABLE_ENABLED &&
          reinstalled.record.total_in == 0u && reinstalled.record.report_seq == 0u,
          "clean uninstall purge followed by reinstall starts a new Enabled state");
}

static void test_v3_rejects_new_command_and_fails_closed(void)
{
    setup_app(NULL, 0u, 0u);
    uint8_t command[LC_CTRL_MSG_BUF_CAP];
    uint32_t len = lcstub_make_command(command, sizeof(command), 5u, 1u, 7u,
                                       1u, 0u, NULL, 0u);
    lcstub_push_command(stub, command, len);
    lc_ctrl_poll(&ctrl);
    check(ctrl.st.wire_rejected == 1u && lcstub_reply_count(stub) == 0,
          "current v3 parser rejects Enable command without a reply");
    teardown_app();

    study_record_t paused = { 0 };
    lc_bus_config_defaults(&paused.cfg);
    paused.total_in = 80u;
    paused.total_out = 40u;
    paused.report_seq = 12u;
    paused.config_generation = 2u;
    paused.enable = STUDY_ENABLE_PAUSED;
    uint8_t schema3[LC_ST_BLOB_MAX];
    uint32_t schema3_len = study_encode_schema3(schema3, sizeof(schema3), &paused);
    setup_app(schema3, schema3_len, 6u);
    check(bus.persist_state == LCBUS_PERSIST_CORRUPT,
          "current v3 sees the candidate schema as corrupt");
    feed_crossing(1, 1u, 100u);
    check(bus.total_in == 0u && bus.window_in == 0u,
          "current v3 does not count FRAME after unsupported paused schema");
    lcstub_set_tick(stub, 400000u);
    lcbus_on_idle(&bus);
    check(bus.report_seq == 0u && stub->report_count == 0,
          "current v3 does not submit a window after unsupported paused schema");
    teardown_app();
}

int main(void)
{
    test_schema_codec_and_crc();
    test_real_migration_and_repeat_start();
    test_real_corrupt_and_unknown_storage();
    test_real_commit_faults_and_cas_conflict();
    test_real_frame_and_idle_report_paths();
    test_candidate_pause_resume_and_both_gates();
    test_candidate_crash_unknown_conflict_and_reinstall();
    test_v3_rejects_new_command_and_fails_closed();
    if (failures != 0) {
        printf("ENABLE-PERSISTENCE-STUDY RESULT: FAIL (%d/%d checks failed)\n",
               failures, checks);
        return 1;
    }
    printf("ENABLE-PERSISTENCE-STUDY RESULT: PASS (%d checks)\n", checks);
    return 0;
}
