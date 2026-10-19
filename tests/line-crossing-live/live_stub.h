
#ifndef LIVE_STUB_H
#define LIVE_STUB_H

#include <stddef.h>
#include <stdint.h>
#include "lc_bus.h"
#include "lc_lvn4.h"

#define LIVE_REC_MAX_PACKETS 4096
#define LIVE_REC_MAX_LEN     9216
#define LIVE_MAX_REPORTS     8
#define LIVE_REPORT_MAX      6144

typedef struct {
    float    x, y, w, h, conf;
    uint32_t class_index;
} live_det_t;

typedef struct {
    uint8_t  bytes[LIVE_REC_MAX_LEN];
    uint32_t len;
    int32_t  rc;
} live_rec_entry_t;

typedef struct {
    live_rec_entry_t  *pkts;
    uint32_t          count;
    int32_t           fail_next;
    uint32_t          fail_times;
} live_recorder_t;

void live_rec_free(live_recorder_t *r);
uint32_t live_rec_count(const live_recorder_t *r);
const uint8_t *live_rec_bytes(const live_recorder_t *r, uint32_t i);
uint32_t live_rec_len(const live_recorder_t *r, uint32_t i);
int32_t live_rec_rc(const live_recorder_t *r, uint32_t i);
void live_rec_fail_next(live_recorder_t *r, int32_t code, uint32_t times);

void *live_malloc(size_t sz);
void  live_free(void *p);
void  live_malloc_fail_after(unsigned long count);
unsigned long live_malloc_count(void);

typedef struct {
    lcbus_t         bus;
    lc_lvn4_t       prod;
    live_recorder_t *rec;
    uint32_t        now_ms;
    uint32_t        model_gen;
    uint32_t        class_gen;
    uint32_t        event_seq;
    uint32_t        boot_id;
    uint8_t         reports[LIVE_MAX_REPORTS][LIVE_REPORT_MAX];
    uint32_t        report_len[LIVE_MAX_REPORTS];
    uint32_t        report_count;
} live_env_t;

live_env_t *live_env_new(void);
void live_env_free(live_env_t *e);

void live_env_arm(live_env_t *e, uint32_t session_gen, uint32_t track_max);

uint32_t live_frame(uint8_t *out, uint32_t cap, uint32_t seq, uint32_t mono_ms,
                    uint32_t model_gen, uint32_t class_gen,
                    uint32_t flags, uint32_t lost,
                    const live_det_t *dets, uint32_t n);

uint32_t live_gap_event(uint8_t *out, uint32_t cap, uint32_t seq, uint32_t mono_ms,
                        uint32_t flags, uint32_t lost);

uint32_t live_model_changed(uint8_t *out, uint32_t cap, uint32_t seq, uint32_t mono_ms);

void live_env_frame(live_env_t *e, uint32_t mono_ms,
                    const live_det_t *dets, uint32_t n);

void live_env_raw(live_env_t *e, const uint8_t *bytes, uint32_t len);

void live_env_idle(live_env_t *e, uint32_t advance_ms);

#endif
