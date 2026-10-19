#include "test_live.h"
#include "host_stub.h"
#include "app_host_live.h"
#include "lc_app_entry_v4.h"
#include "lc_stateblob.h"

int g_pass;
int g_fail;

#define HOST_CAP_LIVE_PUBLISH 0x00000200u

typedef struct {
    uint32_t container_major;
    uint32_t capabilities;
    uint32_t bind_generation;
    uint32_t callback_generation;
    uint32_t live_publish_max;
    uint32_t live_track_max;
    uint32_t live_capacity;
    uint32_t live_track_capacity;
    uint32_t class_count;
    uint8_t key_current;
    uint8_t tbs_current;
    uint8_t running;
    uint8_t bound;
    uint32_t reject_next;
    uint32_t callback_attempts;
    uint32_t first_packet_seq;
    uint32_t accepted;
    int32_t last_result;
} host_session_t;

static uint32_t host_now;

static uint32_t host_now_ms(void *user)
{
    (void)user;
    return host_now;
}

static int host_admission_accepts(const host_session_t *session)
{
    uint64_t closure = 48u + (uint64_t)session->live_track_max * 140u;
    return session->key_current && session->tbs_current &&
           session->container_major == 4u &&
           (session->capabilities & HOST_CAP_LIVE_PUBLISH) != 0u &&
           session->live_publish_max >= 312u &&
           (uint64_t)session->live_publish_max >= closure &&
           session->live_publish_max <= session->live_capacity &&
           session->live_track_max <= session->live_track_capacity;
}

static void bind_host_if_admitted(host_session_t *session)
{
    app_host_live_backend_t backend;
    app_host_live_identity_t identity;
    memset(&backend, 0, sizeof(backend));
    backend.now_ms = host_now_ms;
    app_host_live_init(&backend);
    if (!host_admission_accepts(session)) return;

    memset(&identity, 0, sizeof(identity));
    identity.session_generation = session->bind_generation;
    strcpy(identity.publisher_id, "test-publisher");
    strcpy(identity.app_id, "line-crossing");
    memset(identity.spki_sha256, 0x35, sizeof(identity.spki_sha256));
    memset(identity.tbs_sha256, 0x36, sizeof(identity.tbs_sha256));
    memset(identity.package_sha256, 0x37, sizeof(identity.package_sha256));
    identity.live_publish_max = session->live_publish_max;
    identity.live_track_max = session->live_track_max;
    session->bound = app_host_live_bind(&identity) == APP_HOST_LIVE_OK;
    CHECK(session->bound);
}

static int32_t host_live_publish(void *user, const void *buf, uint32_t len)
{
    host_session_t *session = (host_session_t *)user;
    int32_t result;
    session->callback_attempts++;
    if (session->callback_attempts == 1u && len >= 16u) {
        const uint8_t *p = (const uint8_t *)buf;
        session->first_packet_seq = (uint32_t)p[12] |
                                    ((uint32_t)p[13] << 8) |
                                    ((uint32_t)p[14] << 16) |
                                    ((uint32_t)p[15] << 24);
    }
    if (session->reject_next > 0u) {
        session->reject_next--;
        session->last_result = LC_RET_UNAUTHORIZED;
        return session->last_result;
    }
    if (!session->running || !session->bound || session->container_major != 4u ||
        (session->capabilities & HOST_CAP_LIVE_PUBLISH) == 0u) {
        session->last_result = LC_RET_UNAUTHORIZED;
        return session->last_result;
    }
    result = app_host_live_ingest(buf, len, session->callback_generation,
                                  session->class_count);
    session->last_result = result;
    if (result == APP_HOST_LIVE_OK) session->accepted++;
    return result;
}

static void set_enable_state(lcstub_t *stub, uint32_t enable_state, int corrupt)
{
    lc_bus_config_t cfg;
    uint8_t state[LC_ST_BLOB_MAX];
    lc_bus_config_defaults(&cfg);
    uint32_t len = lc_st_encode_enable(state, sizeof(state), &cfg, 7u, 4u,
                                       2u, 1u, 9u, 1u, enable_state);
    if (corrupt) state[24] ^= 0x20u;
    lcstub_set_state(stub, state, len, 6u);
}

static void set_session(host_session_t *session, uint32_t generation)
{
    memset(session, 0, sizeof(*session));
    session->container_major = 4u;
    session->capabilities = HOST_CAP_LIVE_PUBLISH;
    session->bind_generation = generation;
    session->callback_generation = generation;
    session->live_publish_max = 9008u;
    session->live_track_max = 64u;
    session->live_capacity = 9008u;
    session->live_track_capacity = 64u;
    session->class_count = 2u;
    session->key_current = 1u;
    session->tbs_current = 1u;
    session->running = 1u;
}

static lcstub_t *new_entry_stub(uint32_t enable_state, int corrupt,
                                host_session_t *session)
{
    lcstub_t *stub = lcstub_new();
    stub->auto_stop_after_no_events = 1u;
    lcstub_set_model(stub, 1, 7u, 4u, session->class_count,
                     "od-demo", "1.2");
    lcstub_set_class(stub, 0u, "person");
    set_enable_state(stub, enable_state, corrupt);
    bind_host_if_admitted(session);
    stub->live_publish_hook = host_live_publish;
    stub->live_publish_user = session;
    return stub;
}

static int32_t run_entry(lcstub_t *stub)
{
    lc_app_api_v4_t api;
    lcstub_make_table_v4(stub, &api);
    return app_entry(&api, LC_APP_ABI_V4);
}

static void push_path(lcstub_t *stub)
{
    static const float y[] = {0.30f, 0.44f, 0.58f, 0.72f};
    uint32_t i;
    for (i = 0u; i < sizeof(y) / sizeof(y[0]); i++) {
        lcstub_det_t det = {0.45f, y[i] - 0.02f, 0.1f, 0.04f, 0.9f, 0u};
        lcstub_push_frame(stub, i + 1u, 100u + i * 100u, 7u, 4u,
                          0u, 0u, &det, 1u);
    }
}

static void finish_session(lcstub_t *stub, host_session_t *session)
{
    if (session->bound) app_host_live_end(session->bind_generation);
    lcstub_destroy(stub);
}

static void test_real_entry_publishes_to_host_parser(void)
{
    lcstub_t *stub;
    host_session_t session;
    app_host_live_event_t events[8];
    app_host_live_read_out_t read_info;
    app_host_live_track_t tracks[4];
    app_host_live_snapshot_out_t snapshot_info;

    host_now = 1000u;
    set_session(&session, 8101u);
    stub = new_entry_stub(LC_ST_ENABLE_ENABLED, 0, &session);
    push_path(stub);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK(stub->live_publish_calls > 0u);
    CHECK(session.accepted > 0u);
    CHECK_EQ_I(session.last_result, APP_HOST_LIVE_OK);
    CHECK_EQ_I(app_host_live_read(session.bind_generation, 0u, events, 8u,
                                  &read_info), APP_HOST_LIVE_OK);
    CHECK(read_info.through_seq > 0u);
    CHECK(read_info.source_total > 0u);
    CHECK_EQ_I(app_host_live_snapshot_read(session.bind_generation, tracks, 4u,
                                           &snapshot_info), APP_HOST_LIVE_OK);
    CHECK(snapshot_info.track_count > 0u);
    CHECK_EQ_I(snapshot_info.freshness, APP_HOST_LIVE_FRESHNESS_FRESH);
    finish_session(stub, &session);
}

static void run_rejected_host_entry(host_session_t *session)
{
    lcstub_t *stub = new_entry_stub(LC_ST_ENABLE_ENABLED, 0, session);
    app_host_live_status_t status;
    push_path(stub);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK(stub->live_publish_calls > 0u);
    CHECK_EQ_I(session->accepted, 0u);
    app_host_live_status(&status);
    CHECK_EQ_I(status.packet_count, 0u);
    CHECK_EQ_I(status.event_count, 0u);
    finish_session(stub, session);
}

static void test_host_admission_negatives_fail_closed(void)
{
    host_session_t session;

    set_session(&session, 8201u);
    session.key_current = 0u;
    session.running = 0u;
    run_rejected_host_entry(&session);

    set_session(&session, 8202u);
    session.tbs_current = 0u;
    session.running = 0u;
    run_rejected_host_entry(&session);

    set_session(&session, 8203u);
    session.capabilities = 0x63u;
    run_rejected_host_entry(&session);

    set_session(&session, 8204u);
    session.container_major = 3u;
    session.capabilities = 0x63u;
    run_rejected_host_entry(&session);

    set_session(&session, 8205u);
    session.live_capacity = 312u;
    run_rejected_host_entry(&session);
}

static void test_stale_host_session_is_rejected_by_parser(void)
{
    host_session_t session;
    app_host_live_status_t status;
    lcstub_t *stub;

    set_session(&session, 8301u);
    session.callback_generation = 8302u;
    stub = new_entry_stub(LC_ST_ENABLE_ENABLED, 0, &session);
    push_path(stub);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK(stub->live_publish_calls > 0u);
    CHECK_EQ_I(session.accepted, 0u);
    CHECK_EQ_I(session.last_result, APP_HOST_LIVE_ERR_GENERATION);
    app_host_live_status(&status);
    CHECK_EQ_I(status.packet_count, 0u);
    finish_session(stub, &session);
}

static void push_track_history(lcstub_t *stub, uint32_t track_count,
                               uint32_t transition_count)
{
    lcstub_det_t dets[64];
    uint32_t i;
    uint32_t seq;
    for (i = 0u; i < track_count; i++) {
        dets[i].x = 0.01f + 0.015f * (float)i;
        dets[i].y = 0.38f;
        dets[i].w = 0.01f;
        dets[i].h = 0.04f;
        dets[i].conf = 0.95f;
        dets[i].class_index = 0u;
    }
    for (seq = 1u; seq <= transition_count + 1u; seq++) {
        float y = (seq & 1u) ? 0.40f : 0.60f;
        for (i = 0u; i < track_count; i++) dets[i].y = y - 0.02f;
        lcstub_push_frame(stub, seq, 100u + seq * 100u, 7u, 4u,
                          0u, 0u, dets, track_count);
    }
}

static void test_entry_source_gap(void)
{
    host_session_t session;
    app_host_live_event_t events[64];
    app_host_live_read_out_t read_info;
    app_host_live_track_t tracks[64];
    app_host_live_snapshot_out_t snapshot_info;
    lcstub_t *stub;

    host_now = 2000u;
    set_session(&session, 8401u);
    stub = new_entry_stub(LC_ST_ENABLE_ENABLED, 0, &session);
    push_track_history(stub, 64u, 1u);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK_EQ_I(app_host_live_read(session.bind_generation, 0u, events, 64u,
                                  &read_info), APP_HOST_LIVE_OK);
    CHECK_EQ_I(read_info.through_seq, 64u);
    CHECK_EQ_I(read_info.source_total, 64u);
    CHECK_EQ_I(read_info.source_gap, 48u);
    CHECK_EQ_I(read_info.state, APP_HOST_LIVE_READ_STATE_GAPPED);
    CHECK_EQ_I(app_host_live_snapshot_read(session.bind_generation, tracks, 64u,
                                           &snapshot_info), APP_HOST_LIVE_OK);
    CHECK_EQ_I(snapshot_info.track_count, 64u);
    finish_session(stub, &session);
}

static void test_entry_host_slow_reader(void)
{
    host_session_t session;
    app_host_live_event_t events[64];
    app_host_live_read_out_t read_info;
    lcstub_t *stub;

    host_now = 3000u;
    set_session(&session, 8402u);
    stub = new_entry_stub(LC_ST_ENABLE_ENABLED, 0, &session);
    push_track_history(stub, 16u, 6u);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK_EQ_I(app_host_live_read(session.bind_generation, 0u, events, 64u,
                                  &read_info), APP_HOST_LIVE_OK);
    CHECK_EQ_I(read_info.through_seq, 96u);
    CHECK_EQ_I(read_info.source_gap, 0u);
    CHECK(read_info.host_dropped_events > 0u);
    printf("entry-host-slow state=%u unknown=%u resync=%u dropped=%llu\n",
           (unsigned)read_info.state, (unsigned)read_info.loss_unknown,
           (unsigned)read_info.resync_required,
           (unsigned long long)read_info.host_dropped_events);
    CHECK_EQ_I(read_info.state, APP_HOST_LIVE_READ_STATE_GAPPED);
    finish_session(stub, &session);
}

static void test_entry_lost_callback_then_fresh_resume(void)
{
    host_session_t session;
    app_host_live_event_t events[8];
    app_host_live_read_out_t read_info;
    lcstub_t *stub;
    uint32_t first_run_calls;
    app_host_live_backend_t backend;

    host_now = 4000u;
    set_session(&session, 8451u);
    session.reject_next = 1u;
    stub = new_entry_stub(LC_ST_ENABLE_ENABLED, 0, &session);
    push_path(stub);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK_EQ_I(session.callback_attempts, 1u);
    CHECK_EQ_I(session.accepted, 0u);
    CHECK_EQ_I(session.first_packet_seq, 1u);
    first_run_calls = stub->live_publish_calls;

    memset(&backend, 0, sizeof(backend));
    backend.now_ms = host_now_ms;
    app_host_live_end(session.bind_generation);
    session.bind_generation = 8452u;
    session.callback_generation = 8452u;
    session.callback_attempts = 0u;
    session.first_packet_seq = 0u;
    session.last_result = APP_HOST_LIVE_OK;
    session.bound = 0u;
    bind_host_if_admitted(&session);
    lcstub_set_stop(stub, 0);
    push_path(stub);
    CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
    CHECK(stub->live_publish_calls > first_run_calls);
    CHECK(session.accepted > 0u);
    CHECK_EQ_I(session.first_packet_seq, 1u);
    CHECK_EQ_I(app_host_live_read(session.bind_generation, 0u, events, 8u,
                                  &read_info), APP_HOST_LIVE_OK);
    CHECK(read_info.through_seq > 0u);
    CHECK_EQ_I(read_info.state, APP_HOST_LIVE_READ_STATE_CONTINUOUS);
    finish_session(stub, &session);
}

static void test_real_entry_pause_and_unknown_gates(void)
{
    uint32_t states[] = {LC_ST_ENABLE_PAUSED, LC_ST_ENABLE_PAUSED};
    int corrupt[] = {0, 1};
    uint32_t i;
    for (i = 0u; i < 2u; i++) {
        host_session_t session;
        lcstub_t *stub;
        set_session(&session, 8501u + i);
        stub = new_entry_stub(states[i], corrupt[i], &session);
        push_path(stub);
        CHECK_EQ_I(run_entry(stub), LC_APP_EXIT_OK);
        CHECK_EQ_I(stub->live_publish_calls, 0u);
        CHECK_EQ_I(session.accepted, 0u);
        finish_session(stub, &session);
    }
}

int main(void)
{
    test_real_entry_publishes_to_host_parser();
    test_host_admission_negatives_fail_closed();
    test_stale_host_session_is_rejected_by_parser();
    test_entry_source_gap();
    test_entry_host_slow_reader();
    test_entry_lost_callback_then_fresh_resume();
    test_real_entry_pause_and_unknown_gates();
    TEST_REPORT("line-crossing-live/entry-host-activation");
}
