
#include "ref_decoder.h"

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd_u16(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

int rd_decode(const uint8_t *buf, uint32_t len, uint32_t declared_class_count,
              rd_view_t *out)
{
    if (!buf || !out) return RD_ERR_TRUNCATED;
    if (len < 48u) return RD_ERR_TRUNCATED;

    out->magic[0] = buf[0];
    out->magic[1] = buf[1];
    out->magic[2] = buf[2];
    out->magic[3] = buf[3];
    if (buf[0] != 0x4Cu || buf[1] != 0x56u || buf[2] != 0x4Eu || buf[3] != 0x34u) {
        return RD_ERR_MAGIC;
    }
    out->header_version = rd_u16(buf + 4);
    if (out->header_version != 1u) return RD_ERR_VERSION;
    out->kind = rd_u16(buf + 6);
    if (out->kind != 1u && out->kind != 2u) return RD_ERR_KIND;
    out->total_len = rd_u32(buf + 8);
    if (out->total_len != len) return RD_ERR_LEN;
    out->packet_seq = rd_u32(buf + 12);
    if (out->packet_seq == 0u) return RD_ERR_SEQ;
    out->event_through_seq = rd_u32(buf + 16);
    out->cumulative_event_total = rd_u32(buf + 20);
    out->cumulative_source_gap = rd_u32(buf + 24);
    out->source_ts_ms = rd_u32(buf + 28);
    out->config_generation = rd_u32(buf + 32);
    if (out->config_generation == 0u) return RD_ERR_SEQ;
    out->record_count = rd_u32(buf + 36);
    out->flags = rd_u32(buf + 40);
    if ((out->flags & (uint32_t)0xFFFFFFF8u) != 0u) return RD_ERR_FLAGS;
    out->reserved = rd_u32(buf + 44);
    if (out->reserved != 0u) return RD_ERR_RESERVED;

    if (out->kind == 1u) {
        if (out->record_count > RD_MAX_EVENTS) return RD_ERR_COUNT;
        uint64_t expect = 48u + (uint64_t)out->record_count * 16u;
        if (expect != (uint64_t)len) return RD_ERR_LEN;
        uint32_t i;
        uint32_t prev_seq = 0u;
        for (i = 0; i < out->record_count; i++) {
            const uint8_t *r = buf + 48u + i * 16u;
            rd_event_t *e = &out->events[i];
            e->seq = rd_u32(r + 0);
            e->track_id = rd_u32(r + 4);
            e->ts_ms = rd_u32(r + 8);
            e->direction = r[12];
            e->flags = r[13];
            e->x_q8 = r[14];
            e->y_q8 = r[15];
            if (e->track_id == 0u) return RD_ERR_RECORD;
            if (e->direction != 1u && e->direction != 2u) return RD_ERR_DIRECTION;
            if ((e->flags & (uint8_t)0xFEu) != 0u) return RD_ERR_FLAGS;
            if (e->seq <= prev_seq) return RD_ERR_SEQ;
            if (e->seq > out->event_through_seq) return RD_ERR_SEQ;
            prev_seq = e->seq;
        }
        return 0;
    }

    if (out->record_count > RD_MAX_TRACKS) return RD_ERR_COUNT;
    const uint8_t *cur = buf + 48u;
    const uint8_t *end = buf + len;
    uint32_t i;
    for (i = 0; i < out->record_count; i++) {
        if ((uint64_t)(end - cur) < 12u) return RD_ERR_TRUNCATED;
        rd_track_t *t = &out->tracks[i];
        t->track_id = rd_u32(cur + 0);
        t->point_count = rd_u16(cur + 4);
        t->class_index = rd_u16(cur + 6);
        t->state = cur[8];
        t->flags = cur[9];
        t->confidence_q16 = rd_u16(cur + 10);
        if (t->track_id == 0u) return RD_ERR_RECORD;
        if (t->point_count > RD_MAX_POINTS) return RD_ERR_RECORD;
        if (t->state != 1u) return RD_ERR_STATE;
        if (t->flags != 0u) return RD_ERR_FLAGS;
        if (t->class_index != 0xFFFFu &&
            (declared_class_count == 0u || t->class_index >= declared_class_count)) {
            return RD_ERR_CLASS;
        }
        uint32_t j;
        for (j = 0; j < i; j++) {
            if (out->tracks[j].track_id == t->track_id) return RD_ERR_DUPLICATE;
        }
        cur += 12u;
        if ((uint64_t)(end - cur) < (uint64_t)t->point_count * 8u) return RD_ERR_TRUNCATED;
        for (j = 0; j < t->point_count; j++) {
            t->pts[j].ts_ms = rd_u32(cur + 0);
            t->pts[j].x_q16 = rd_u16(cur + 4);
            t->pts[j].y_q16 = rd_u16(cur + 6);
            cur += 8u;
        }
    }
    if (cur != end) return RD_ERR_LEN;
    return 0;
}
