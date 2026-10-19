#include "test_live.h"
#include "live_stub.h"
#include "app_host_live.h"

int g_pass;
int g_fail;

static uint32_t host_now;
static const char *fixture_dir;

static uint32_t host_now_ms(void *ctx)
{
    return *(uint32_t *)ctx;
}

static uint32_t get_u16(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int write_fixture(const char *name, const uint8_t *bytes, uint32_t len)
{
    char path[512];
    FILE *fp;
    int written;
    int closed;
    if (!fixture_dir) return -1;
    int n = snprintf(path, sizeof(path), "%s/%s", fixture_dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    fp = fopen(path, "wb");
    if (!fp) return -1;
    written = fwrite(bytes, 1u, len, fp) == len;
    closed = fclose(fp) == 0;
    return written && closed ? 0 : -1;
}

static app_host_live_identity_t identity(uint32_t session, uint32_t publish_max,
                                         uint32_t track_max, uint8_t seed)
{
    app_host_live_identity_t out;
    memset(&out, 0, sizeof(out));
    out.session_generation = session;
    strcpy(out.publisher_id, "trusted-test-owner");
    strcpy(out.app_id, "line-crossing");
    memset(out.spki_sha256, seed, sizeof(out.spki_sha256));
    memset(out.tbs_sha256, (uint8_t)(seed + 1u), sizeof(out.tbs_sha256));
    memset(out.package_sha256, (uint8_t)(seed + 2u), sizeof(out.package_sha256));
    out.live_publish_max = publish_max;
    out.live_track_max = track_max;
    return out;
}

static int bind_host(uint32_t session, uint32_t publish_max, uint32_t track_max,
                     uint8_t seed)
{
    app_host_live_backend_t backend;
    app_host_live_identity_t id = identity(session, publish_max, track_max, seed);
    memset(&backend, 0, sizeof(backend));
    backend.ctx = &host_now;
    backend.now_ms = host_now_ms;
    app_host_live_init(&backend);
    return app_host_live_bind(&id);
}

static live_det_t person(float x, float y)
{
    live_det_t d;
    d.x = x - 0.02f;
    d.y = y - 0.02f;
    d.w = 0.04f;
    d.h = 0.04f;
    d.conf = 0.9f;
    d.class_index = 1u;
    return d;
}

static void ingest_new(live_env_t *e, uint32_t *cursor, uint32_t session,
                       int32_t expected)
{
    while (*cursor < live_rec_count(e->rec)) {
        int32_t rc = app_host_live_ingest(live_rec_bytes(e->rec, *cursor),
                                          live_rec_len(e->rec, *cursor),
                                          session, 2u);
        CHECK_EQ_I(rc, expected);
        (*cursor)++;
    }
}

static live_env_t *make_full_tracks(uint32_t session)
{
    live_env_t *e = live_env_new();
    live_det_t row[64];
    lc_bus_config_t cfg;
    uint32_t i, f;
    if (!e) return NULL;
    cfg = e->bus.cfg;
    cfg.track_history_k = 16u;
    CHECK_EQ_I(lcbus_apply_config(&e->bus, &cfg), 0);
    live_env_arm(e, session, 64u);
    for (f = 0u; f < 17u; f++) {
        for (i = 0u; i < 64u; i++) row[i] = person(0.02f + 0.015f * (float)i, 0.42f);
        live_env_frame(e, 1000u + f * 100u, row, 64u);
    }
    for (i = 0u; i < 64u; i++) row[i] = person(0.02f + 0.015f * (float)i, 0.58f);
    live_env_frame(e, 2800u, row, 64u);
    return e;
}

static void write_regular_event_fixture(void)
{
    live_env_t *e = live_env_new();
    live_det_t d;
    uint32_t cursor = 0u;
    uint32_t i;
    int wrote = 0;
    CHECK_EQ_I(bind_host(7002u, 9008u, 64u, 0x35u), APP_HOST_LIVE_OK);
    CHECK(e != NULL);
    if (!e) return;
    host_now = 20000u;
    live_env_arm(e, 7002u, 64u);
    for (i = 0u; i < 17u; i++) {
        d = person(0.5f, 0.42f);
        live_env_frame(e, 1000u + i * 100u, &d, 1u);
    }
    d = person(0.5f, 0.58f);
    live_env_frame(e, 2800u, &d, 1u);
    ingest_new(e, &cursor, 7002u, APP_HOST_LIVE_OK);
    for (i = 0u; i < live_rec_count(e->rec); i++) {
        const uint8_t *p = live_rec_bytes(e->rec, i);
        if (get_u16(p + 6u) == APP_HOST_LIVE_KIND_EVENT_BATCH &&
            get_u32(p + 36u) > 0u && get_u32(p + 24u) == 0u) {
            CHECK_EQ_I(write_fixture("kind1-event-batch.bin", p,
                                     live_rec_len(e->rec, i)), 0);
            wrote = 1;
            break;
        }
    }
    CHECK(wrote);
    live_env_free(e);
}

static void test_same_bytes_parser_and_cursor(void)
{
    live_env_t *e;
    uint32_t cursor = 0u;
    uint32_t i;
    uint32_t event_packets = 0u;
    uint32_t track_packets = 0u;
    uint32_t zero_track_packets = 0u;
    uint32_t gap_packets = 0u;
    int saw_full_64x16 = 0;
    int wrote_tracks = 0;
    int wrote_gap = 0;
    app_host_live_event_t events[128];
    app_host_live_read_out_t read_info;
    app_host_live_track_t tracks[64];
    app_host_live_snapshot_out_t snapshot_info;

    CHECK_EQ_I(bind_host(7001u, 9008u, 64u, 0x31u), APP_HOST_LIVE_OK);
    host_now = 100u;
    e = make_full_tracks(7001u);
    CHECK(e != NULL);
    if (!e) return;
    ingest_new(e, &cursor, 7001u, APP_HOST_LIVE_OK);

    for (i = 0u; i < live_rec_count(e->rec); i++) {
        const uint8_t *p = live_rec_bytes(e->rec, i);
        uint32_t kind = get_u16(p + 6u);
        uint32_t count = get_u32(p + 36u);
        if (kind == APP_HOST_LIVE_KIND_EVENT_BATCH) {
            event_packets++;
            if ((get_u32(p + 40u) & APP_HOST_LIVE_FLAG_SOURCE_GAP_DELTA) != 0u &&
                get_u32(p + 24u) == 48u && get_u32(p + 16u) == 64u) {
                gap_packets++;
                CHECK_EQ_I(write_fixture("kind1-source-gap.bin", p,
                                         live_rec_len(e->rec, i)), 0);
                wrote_gap = 1;
            }
        } else if (kind == APP_HOST_LIVE_KIND_TRACKS_SNAPSHOT) {
            track_packets++;
            if (count == 0u) zero_track_packets++;
            if (count == 64u && live_rec_len(e->rec, i) == 9008u) {
                saw_full_64x16 = 1;
                if (!wrote_tracks) {
                    CHECK_EQ_I(write_fixture("kind2-tracks-64x16.bin", p,
                                             live_rec_len(e->rec, i)), 0);
                    wrote_tracks = 1;
                }
            }
        }
    }
    CHECK(wrote_tracks);
    CHECK(wrote_gap);
    CHECK(event_packets > 0u);
    CHECK(track_packets > 0u);
    CHECK_EQ_I(gap_packets, 1u);
    CHECK(saw_full_64x16);
    CHECK_EQ_I(app_host_live_snapshot_read(7001u, tracks, 64u, &snapshot_info),
               APP_HOST_LIVE_OK);
    CHECK_EQ_I(snapshot_info.track_count, 64u);
    CHECK_EQ_I(snapshot_info.freshness, APP_HOST_LIVE_FRESHNESS_FRESH);
    host_now = 10101u;
    CHECK_EQ_I(app_host_live_snapshot_read(7001u, tracks, 64u, &snapshot_info),
               APP_HOST_LIVE_OK);
    CHECK_EQ_I(snapshot_info.freshness, APP_HOST_LIVE_FRESHNESS_STALE);
    CHECK_EQ_I(snapshot_info.age_ms, 10001u);

    host_now = 10102u;
    for (i = 0u; i < 24u; i++) {
        live_env_frame(e, 400u + i * 10u, NULL, 0u);
        ingest_new(e, &cursor, 7001u, APP_HOST_LIVE_OK);
    }
    for (i = 0u; i < live_rec_count(e->rec); i++) {
        const uint8_t *p = live_rec_bytes(e->rec, i);
        if (get_u16(p + 6u) == APP_HOST_LIVE_KIND_TRACKS_SNAPSHOT &&
            get_u32(p + 36u) == 0u) {
            zero_track_packets++;
            if (write_fixture("kind2-zero-track.bin", p,
                              live_rec_len(e->rec, i)) == 0) break;
        }
    }
    CHECK(zero_track_packets > 0u);
    CHECK_EQ_I(app_host_live_read(7001u, 0u, events, 128u, &read_info),
               APP_HOST_LIVE_OK);
    CHECK_EQ_I(read_info.through_seq, 64u);
    CHECK_EQ_I(read_info.source_total, 64u);
    CHECK_EQ_I(read_info.source_gap, 48u);
    CHECK_EQ_I(read_info.state, APP_HOST_LIVE_READ_STATE_GAPPED);
    CHECK_EQ_I(app_host_live_snapshot_read(7001u, tracks, 64u, &snapshot_info),
               APP_HOST_LIVE_OK);
    CHECK_EQ_I(snapshot_info.track_count, 0u);
    CHECK_EQ_I(snapshot_info.session_generation, 7001u);
    live_env_free(e);
    app_host_live_end(7001u);
    write_regular_event_fixture();
    printf("joint/same-byte kind1 kind2 zero-track source-gap cursor done\n");
}

static void test_capacity_v3_session_tbs_and_revoke(void)
{
    live_env_t *e;
    uint8_t v3[48];
    app_host_live_identity_t next;
    app_host_live_status_t status;

    CHECK_EQ_I(bind_host(7101u, 312u, 1u, 0x41u), APP_HOST_LIVE_OK);
    e = make_full_tracks(7101u);
    CHECK(e != NULL);
    if (!e) return;
    CHECK_EQ_I(app_host_live_ingest(live_rec_bytes(e->rec, 0u),
                                    live_rec_len(e->rec, 0u), 7101u, 2u),
               APP_HOST_LIVE_OK);
    CHECK_EQ_I(app_host_live_ingest(live_rec_bytes(e->rec, 1u),
                                    live_rec_len(e->rec, 1u), 7101u, 2u),
               APP_HOST_LIVE_ERR_LENGTH);
    CHECK_EQ_I(bind_host(7102u, 0u, 0u, 0x51u), APP_HOST_LIVE_ERR_PARAM);
    CHECK_EQ_I(bind_host(7101u, 312u, 1u, 0x41u), APP_HOST_LIVE_OK);

    memset(v3, 0, sizeof(v3));
    memcpy(v3, "NFC3", 4u);
    v3[8] = 48u;
    CHECK_EQ_I(app_host_live_ingest(v3, sizeof(v3), 7101u, 2u),
               APP_HOST_LIVE_ERR_HEADER);

    app_host_live_end(7101u);
    next = identity(7103u, 9008u, 64u, 0x61u);
    CHECK_EQ_I(app_host_live_bind(&next), APP_HOST_LIVE_OK);
    CHECK_EQ_I(app_host_live_ingest(live_rec_bytes(e->rec, 2u),
                                    live_rec_len(e->rec, 2u), 7101u, 2u),
               APP_HOST_LIVE_ERR_GENERATION);
    app_host_live_status(&status);
    CHECK_EQ_I(status.session_generation, 7103u);
    CHECK(status.tbs_sha256[0] == 0x62u);
    app_host_live_end(7103u);
    CHECK_EQ_I(app_host_live_ingest(live_rec_bytes(e->rec, 3u),
                                    live_rec_len(e->rec, 3u), 7103u, 2u),
               APP_HOST_LIVE_ERR_UNBOUND);
    live_env_free(e);
    printf("joint/capacity legacy-session-tbs-context revoke done\n");
}

static void test_host_slow_reader_gap(void)
{
    live_env_t *e;
    live_det_t d;
    uint32_t cursor = 0u;
    uint32_t i;
    app_host_live_event_t events[128];
    app_host_live_read_out_t read_info;

    CHECK_EQ_I(bind_host(7201u, 9008u, 64u, 0x71u), APP_HOST_LIVE_OK);
    e = live_env_new();
    CHECK(e != NULL);
    if (!e) return;
    live_env_arm(e, 7201u, 64u);
    for (i = 0u; i < 220u; i++) {
        d = person(0.5f, (i & 1u) ? 0.60f : 0.40f);
        live_env_frame(e, 1000u + i * 100u, &d, 1u);
        ingest_new(e, &cursor, 7201u, APP_HOST_LIVE_OK);
    }
    CHECK(e->prod.cumulative_total >= 64u);
    CHECK_EQ_I(app_host_live_read(7201u, 0u, events, 128u, &read_info),
               APP_HOST_LIVE_OK);
    CHECK(read_info.host_dropped_events > 0u);
    CHECK_EQ_I(read_info.state, APP_HOST_LIVE_READ_STATE_GAPPED);
    CHECK(read_info.oldest_cursor > 1u);
    live_env_free(e);
    printf("joint/host-slow-reader gap done\n");
}

int main(int argc, char **argv)
{
    int rc;
    if (argc != 2) return 2;
    fixture_dir = argv[1];
    test_same_bytes_parser_and_cursor();
    test_capacity_v3_session_tbs_and_revoke();
    test_host_slow_reader_gap();
    rc = (g_fail == 0) ? 0 : 1;
    printf("[line-crossing-live/host-joint] pass=%d fail=%d -> %s\n",
           g_pass, g_fail, rc == 0 ? "PASS" : "FAIL");
    return rc;
}
