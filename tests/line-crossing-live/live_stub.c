
#include "live_stub.h"
#include <stdlib.h>
#include <string.h>

static uint32_t wr32_mem(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
    return 4u;
}

static uint32_t wr_f32_mem(uint8_t *p, float f)
{
    union { float f; uint32_t u; } c;
    c.f = f;
    return wr32_mem(p, c.u);
}

static unsigned long g_live_malloc_count;
static unsigned long g_live_malloc_fail_after;
static unsigned long g_live_malloc_served;

void *live_malloc(size_t sz)
{
    g_live_malloc_count++;
    if (g_live_malloc_fail_after != 0UL && g_live_malloc_served >= g_live_malloc_fail_after) {
        return NULL;
    }
    g_live_malloc_served++;
    return malloc(sz);
}

void live_free(void *p)
{
    free(p);
}

void live_malloc_fail_after(unsigned long count)
{
    g_live_malloc_fail_after = count;
}

unsigned long live_malloc_count(void)
{
    return g_live_malloc_count;
}

void live_rec_free(live_recorder_t *r)
{
    if (!r) return;
    free(r->pkts);
    free(r);
}

uint32_t live_rec_count(const live_recorder_t *r)
{
    return r ? r->count : 0u;
}

const uint8_t *live_rec_bytes(const live_recorder_t *r, uint32_t i)
{
    if (!r || i >= r->count) return NULL;
    return r->pkts[i].bytes;
}

uint32_t live_rec_len(const live_recorder_t *r, uint32_t i)
{
    if (!r || i >= r->count) return 0u;
    return r->pkts[i].len;
}

int32_t live_rec_rc(const live_recorder_t *r, uint32_t i)
{
    if (!r || i >= r->count) return 0;
    return r->pkts[i].rc;
}

void live_rec_fail_next(live_recorder_t *r, int32_t code, uint32_t times)
{
    if (!r) return;
    r->fail_next = code;
    r->fail_times = times;
}

static int32_t rec_publish(void *user, const void *buf, uint32_t len)
{
    live_recorder_t *r = (live_recorder_t *)user;
    if (r->fail_times > 0u) {
        int32_t code = r->fail_next;
        r->fail_times--;
        if (r->fail_times == 0u) r->fail_next = 0;
        return code;
    }
    if (r->count < LIVE_REC_MAX_PACKETS && len <= LIVE_REC_MAX_LEN) {
        live_rec_entry_t *e = &r->pkts[r->count];
        memcpy(e->bytes, buf, len);
        e->len = len;
        e->rc = 0;
        r->count++;
    }
    return 0;
}

static int32_t op_model_meta(void *user, uint8_t *out128)
{
    live_env_t *e = (live_env_t *)user;
    memset(out128, 0, 128u);
    if (e->model_gen == 0u) return -4;
    wr32_mem(out128 + 0, 1u);
    wr32_mem(out128 + 4, 1u);
    wr32_mem(out128 + 8, e->model_gen);
    wr32_mem(out128 + 12, e->class_gen);
    wr32_mem(out128 + 16, 2u);
    memcpy(out128 + 24, "tiny-yolo", 9u);
    memcpy(out128 + 88, "1.0.0", 5u);
    return 0;
}

static int32_t op_class_name(void *user, uint32_t model_gen, uint32_t class_gen,
                             uint32_t class_index, char *out_utf8, uint32_t cap,
                             uint32_t *actual_len)
{
    live_env_t *e = (live_env_t *)user;
    (void)model_gen;
    (void)class_gen;
    if (class_index >= 2u) return -4;
    const char *name = (class_index == 1u) ? "person" : "other";
    uint32_t n = (uint32_t)strlen(name);
    if (cap < n + 1u) return -2;
    memcpy(out_utf8, name, n + 1u);
    if (actual_len) *actual_len = n;
    (void)e;
    return 0;
}

static uint32_t op_tick_ms(void *user)
{
    live_env_t *e = (live_env_t *)user;
    return e->now_ms;
}

static int32_t op_state_read(void *user, uint8_t *out, uint32_t cap,
                             uint32_t *actual_len, uint32_t *out_revision)
{
    live_env_t *e = (live_env_t *)user;
    (void)out;
    (void)cap;
    (void)actual_len;
    (void)out_revision;
    (void)e;
    return 2;
}

static int32_t op_state_commit(void *user, const uint8_t *blob, uint32_t len,
                               uint32_t expected_revision, uint32_t *new_revision)
{
    live_env_t *e = (live_env_t *)user;
    (void)blob;
    (void)len;
    (void)expected_revision;
    e->bus.revision++;
    if (new_revision) *new_revision = e->bus.revision;
    return 0;
}

static int32_t op_report_submit(void *user, const uint8_t *json, uint32_t len,
                                uint32_t app_report_seq, uint32_t *out_host_boot_id)
{
    live_env_t *e = (live_env_t *)user;
    if (e->report_count < LIVE_MAX_REPORTS && len <= LIVE_REPORT_MAX) {
        memcpy(e->reports[e->report_count], json, len);
        e->report_len[e->report_count] = len;
        e->report_count++;
    }
    if (out_host_boot_id) *out_host_boot_id = e->boot_id;
    (void)app_report_seq;
    return 0;
}

static int32_t op_report_status(void *user, uint32_t host_boot_id, uint32_t report_seq,
                                uint32_t *out_mqtt_state, uint32_t *out_webhook_state)
{
    live_env_t *e = (live_env_t *)user;
    (void)host_boot_id;
    (void)report_seq;
    if (out_mqtt_state) *out_mqtt_state = 2u;
    if (out_webhook_state) *out_webhook_state = 2u;
    (void)e;
    return 0;
}

static void op_log(void *user, const char *text)
{
    (void)user;
    (void)text;
}

static void live_obs_forward(void *user, const lcbus_live_facts_t *facts)
{
    lc_lvn4_observe((lc_lvn4_t *)user, facts);
}

live_env_t *live_env_new(void)
{
    live_env_t *e = (live_env_t *)calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->rec = (live_recorder_t *)calloc(1, sizeof(live_recorder_t));
    if (!e->rec) {
        free(e);
        return NULL;
    }
    e->rec->pkts = (live_rec_entry_t *)calloc(LIVE_REC_MAX_PACKETS, sizeof(live_rec_entry_t));
    if (!e->rec->pkts) {
        free(e->rec);
        free(e);
        return NULL;
    }
    e->model_gen = 7u;
    e->class_gen = 3u;
    e->boot_id = 42u;

    lcbus_host_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.user = e;
    ops.model_meta = op_model_meta;
    ops.class_name = op_class_name;
    ops.tick_ms = op_tick_ms;
    ops.state_read = op_state_read;
    ops.state_commit = op_state_commit;
    ops.report_submit = op_report_submit;
    ops.report_status = op_report_status;
    ops.log = op_log;

    lcbus_init(&e->bus, &ops);
    e->bus.state_schema = 2u;
    e->bus.config_generation = 1u;
    lcbus_restore(&e->bus);
    lcbus_rebind(&e->bus, 1);
    lc_lvn4_init(&e->prod, &e->bus, rec_publish, e->rec);
    lcbus_set_live_observer(&e->bus, live_obs_forward, &e->prod);
    return e;
}

void live_env_free(live_env_t *e)
{
    if (!e) return;
    live_rec_free(e->rec);
    free(e);
}

void live_env_arm(live_env_t *e, uint32_t session_gen, uint32_t track_max)
{
    uint32_t closure = 48u + track_max * (12u + 16u * 8u);
    uint32_t publish_max = (closure < 312u) ? 312u : closure;
    lc_lvn4_grant_t g;
    g.session_generation = session_gen;
    g.live_publish_max = publish_max;
    g.live_track_max = track_max;
    (void)lc_lvn4_arm(&e->prod, &g);
}

uint32_t live_frame(uint8_t *out, uint32_t cap, uint32_t seq, uint32_t mono_ms,
                    uint32_t model_gen, uint32_t class_gen,
                    uint32_t flags, uint32_t lost,
                    const live_det_t *dets, uint32_t n)
{
    uint32_t len = 40u + n * 24u;
    if (cap < len) return 0u;
    uint8_t *p = out;
    p += wr32_mem(p, len);
    p += wr32_mem(p, 1u);
    p += wr32_mem(p, seq);
    p += wr32_mem(p, mono_ms);
    p += wr32_mem(p, model_gen);
    p += wr32_mem(p, class_gen);
    p += wr32_mem(p, flags);
    p += wr32_mem(p, n);
    p += wr32_mem(p, lost);
    p += wr32_mem(p, 0u);
    uint32_t i;
    for (i = 0; i < n; i++) {
        p += wr_f32_mem(p, dets[i].x);
        p += wr_f32_mem(p, dets[i].y);
        p += wr_f32_mem(p, dets[i].w);
        p += wr_f32_mem(p, dets[i].h);
        p += wr_f32_mem(p, dets[i].conf);
        p += wr32_mem(p, dets[i].class_index);
    }
    return len;
}

uint32_t live_gap_event(uint8_t *out, uint32_t cap, uint32_t seq, uint32_t mono_ms,
                        uint32_t flags, uint32_t lost)
{
    if (cap < 40u) return 0u;
    uint8_t *p = out;
    p += wr32_mem(p, 40u);
    p += wr32_mem(p, 3u);
    p += wr32_mem(p, seq);
    p += wr32_mem(p, mono_ms);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, flags);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, lost);
    p += wr32_mem(p, 0u);
    return 40u;
}

uint32_t live_model_changed(uint8_t *out, uint32_t cap, uint32_t seq, uint32_t mono_ms)
{
    if (cap < 40u) return 0u;
    uint8_t *p = out;
    p += wr32_mem(p, 40u);
    p += wr32_mem(p, 2u);
    p += wr32_mem(p, seq);
    p += wr32_mem(p, mono_ms);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, 0u);
    p += wr32_mem(p, 0u);
    return 40u;
}

void live_env_frame(live_env_t *e, uint32_t mono_ms,
                    const live_det_t *dets, uint32_t n)
{
    uint8_t buf[2048];
    e->event_seq++;
    uint32_t len = live_frame(buf, (uint32_t)sizeof(buf), e->event_seq, mono_ms,
                              e->model_gen, e->class_gen, 0u, 0u, dets, n);
    if (len) lcbus_on_event(&e->bus, buf, len);
}

void live_env_raw(live_env_t *e, const uint8_t *bytes, uint32_t len)
{
    e->event_seq++;
    lcbus_on_event(&e->bus, bytes, len);
}

void live_env_idle(live_env_t *e, uint32_t advance_ms)
{
    e->now_ms += advance_ms;
    lcbus_on_idle(&e->bus);
}
