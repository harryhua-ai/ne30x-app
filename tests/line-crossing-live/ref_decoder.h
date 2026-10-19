
#ifndef REF_DECODER_H
#define REF_DECODER_H

#include <stdint.h>

#define RD_ERR_TRUNCATED      (-1)
#define RD_ERR_MAGIC          (-2)
#define RD_ERR_VERSION        (-3)
#define RD_ERR_KIND           (-4)
#define RD_ERR_LEN            (-5)
#define RD_ERR_RESERVED       (-6)
#define RD_ERR_FLAGS          (-7)
#define RD_ERR_SEQ            (-8)
#define RD_ERR_RECORD         (-9)
#define RD_ERR_DUPLICATE      (-10)
#define RD_ERR_CLASS          (-11)
#define RD_ERR_DIRECTION      (-12)
#define RD_ERR_STATE          (-13)
#define RD_ERR_COUNT          (-14)

#define RD_MAX_EVENTS 16u
#define RD_MAX_TRACKS 64u
#define RD_MAX_POINTS 16u

typedef struct {
    uint32_t seq;
    uint32_t track_id;
    uint32_t ts_ms;
    uint8_t  direction;
    uint8_t  flags;
    uint8_t  x_q8;
    uint8_t  y_q8;
} rd_event_t;

typedef struct {
    uint32_t track_id;
    uint16_t point_count;
    uint16_t class_index;
    uint8_t  state;
    uint8_t  flags;
    uint16_t confidence_q16;
    struct {
        uint32_t ts_ms;
        uint16_t x_q16;
        uint16_t y_q16;
    } pts[RD_MAX_POINTS];
} rd_track_t;

typedef struct {
    uint8_t  magic[4];
    uint16_t header_version;
    uint16_t kind;
    uint32_t total_len;
    uint32_t packet_seq;
    uint32_t event_through_seq;
    uint32_t cumulative_event_total;
    uint32_t cumulative_source_gap;
    uint32_t source_ts_ms;
    uint32_t config_generation;
    uint32_t record_count;
    uint32_t flags;
    uint32_t reserved;
    rd_event_t events[RD_MAX_EVENTS];
    rd_track_t tracks[RD_MAX_TRACKS];
} rd_view_t;

int rd_decode(const uint8_t *buf, uint32_t len, uint32_t declared_class_count,
              rd_view_t *out);

#endif
