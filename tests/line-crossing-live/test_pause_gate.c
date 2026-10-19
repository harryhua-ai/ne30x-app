#include "test_live.h"
#include "host_stub.h"
#include "lc_app_entry_v4.h"
#include "lc_lvn4.h"
#include "lc_stateblob.h"

int g_pass;
int g_fail;

typedef struct {
    uint32_t count;
    uint8_t first[LC_LVN4_PKT_MAX];
    uint32_t first_len;
} capture_t;

static int32_t publish(void *user, const void *buf, uint32_t len)
{
    capture_t *capture = (capture_t *)user;
    if (capture->count == 0u && len <= sizeof(capture->first)) {
        memcpy(capture->first, buf, len);
        capture->first_len = len;
    }
    capture->count++;
    return 0;
}

static void observe(void *user, const lcbus_live_facts_t *facts)
{
    lc_lvn4_observe((lc_lvn4_t *)user, facts);
}

static uint32_t make_state(uint8_t *out, uint32_t state)
{
    lc_bus_config_t cfg;
    lc_bus_config_defaults(&cfg);
    return lc_st_encode_enable(out, LC_ST_BLOB_MAX, &cfg, 7u, 4u, 2u, 1u,
                               9u, 1u, state);
}

static void setup_bus(lcstub_t *stub, lc_app_api_v4_t *api, lcbus_t *bus,
                     const uint8_t *state, uint32_t state_len)
{
    lcstub_make_table_v4(stub, api);
    lcstub_set_model(stub, 1, 7u, 3u, 1u, "od-demo", "1.2");
    lcstub_set_class(stub, 0u, "person");
    lcstub_set_state(stub, state, state_len, 6u);
    lcbus_host_ops_t ops = *lcbus_abi_ops_v4();
    ops.user = api;
    lcbus_init(bus, &ops);
    bus->state_schema = LC_ST_BLOB_SCHEMA_ENABLE;
    bus->enable_state = LCBUS_ENABLE_UNKNOWN;
    bus->config_generation = 1u;
    lcbus_restore(bus);
    lcbus_rebind(bus, 1);
}

static void setup_producer(lcbus_t *bus, lc_lvn4_t *producer,
                           capture_t *capture, lc_lvn4_gate_t gate)
{
    lc_lvn4_profile_t fixture_profile = { 9901u, 9008u, 64u };
    lc_lvn4_init(producer, bus, publish, capture);
    CHECK_EQ_I(lc_lvn4_arm(producer, &fixture_profile), 0);
    lc_lvn4_set_gate(producer, gate);
    lcbus_set_live_observer(bus, observe, producer);
}

static void deliver_frame(lcstub_t *stub, lcbus_t *bus, uint32_t seq,
                          uint32_t mono_ms, float y)
{
    lcstub_det_t detection = { 0.45f, y - 0.02f, 0.1f, 0.04f, 0.9f, 0u };
    uint8_t event[LC_APP_EVENT_BUF_CAP];
    int slot;
    uint32_t len;
    lcstub_push_frame(stub, seq, mono_ms, 7u, 3u, 0u, 0u, &detection, 1u);
    slot = stub->ev_head;
    len = stub->event_len[slot];
    memcpy(event, stub->events[slot], len);
    stub->ev_head = (stub->ev_head + 1) % LCSTUB_MAX_EVENTS;
    stub->ev_count--;
    lcbus_on_event(bus, event, len);
}

static void deliver_path(lcstub_t *stub, lcbus_t *bus, uint32_t base_seq)
{
    static const float y[] = { 0.30f, 0.44f, 0.58f, 0.72f };
    uint32_t i;
    for (i = 0u; i < sizeof(y) / sizeof(y[0]); i++) {
        deliver_frame(stub, bus, base_seq + i, 100u + i * 100u, y[i]);
    }
}

static void test_paused_frame_idle_and_resume(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcbus_t bus;
    lc_lvn4_t producer;
    capture_t capture;
    uint8_t state[LC_ST_BLOB_MAX];
    uint32_t state_len = make_state(state, LC_ST_ENABLE_PAUSED);
    uint32_t new_revision = 0u;
    memset(&capture, 0, sizeof(capture));
    setup_bus(stub, &api, &bus, state, state_len);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_OK);
    CHECK_EQ_I(bus.enable_state, LC_ST_ENABLE_PAUSED);
    setup_producer(&bus, &producer, &capture, LC_LVN4_GATE_PAUSED);
    deliver_path(stub, &bus, 1u);
    lcstub_set_tick(stub, 400000u);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(capture.count, 0u);
    CHECK_EQ_I(bus.total_in, 7u);
    CHECK_EQ_I(bus.total_out, 4u);
    CHECK_EQ_I(bus.report_seq, 9u);

    CHECK_EQ_I(lcbus_enable_set(&bus, LC_ST_ENABLE_ENABLED,
                                bus.config_generation, bus.revision,
                                &new_revision), LCBUS_TXN_OK);
    CHECK_EQ_I(bus.enable_state, LC_ST_ENABLE_ENABLED);
    CHECK_EQ_I(new_revision, bus.revision);
    lc_lvn4_set_gate(&producer, LC_LVN4_GATE_OPEN);
    deliver_path(stub, &bus, 10u);
    CHECK(capture.count >= 2u);
    CHECK_EQ_I(capture.first_len >= LC_LVN4_HEADER_SIZE, 1);
    CHECK_EQ_I(capture.first[LC_LVN4_OFF_FLAGS], 4u);
    CHECK_EQ_I(capture.first[LC_LVN4_OFF_FLAGS + 1u], 0u);
    lcstub_destroy(stub);
}

static void test_unknown_frame_idle_gate(void)
{
    lcstub_t *stub = lcstub_new();
    lc_app_api_v4_t api;
    lcbus_t bus;
    lc_lvn4_t producer;
    capture_t capture;
    uint8_t state[LC_ST_BLOB_MAX];
    uint32_t state_len = make_state(state, LC_ST_ENABLE_PAUSED);
    memset(&capture, 0, sizeof(capture));
    state[24] ^= 0x20u;
    setup_bus(stub, &api, &bus, state, state_len);
    CHECK_EQ_I(bus.persist_state, LCBUS_PERSIST_CORRUPT);
    CHECK_EQ_I(bus.enable_state, LCBUS_ENABLE_UNKNOWN);
    setup_producer(&bus, &producer, &capture, LC_LVN4_GATE_UNKNOWN);
    deliver_path(stub, &bus, 20u);
    lcstub_set_tick(stub, 500000u);
    lcbus_on_idle(&bus);
    CHECK_EQ_I(capture.count, 0u);
    CHECK_EQ_I(bus.report_seq, 0u);
    lcstub_destroy(stub);
}

int main(void)
{
    test_paused_frame_idle_and_resume();
    test_unknown_frame_idle_gate();
    printf("[line-crossing-live/paused-gate] pass=%d fail=%d -> %s\n",
           g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
