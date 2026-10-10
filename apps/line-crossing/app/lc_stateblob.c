/*
 * lc_stateblob.c — explicit little-endian serialization + CRC-32.
 *
 * Layout (all little-endian):
 *   0  : magic 'LCAS'
 *   4  : schema_version (1)
 *   8  : crc32 (reflected IEEE) over [12 .. len)
 *   12 : target_class_name[32] NUL-padded
 *   44 : counter_name[64] NUL-padded
 *   108: line_x1..y2, outside_x/outside_y permille (6 x u16)
 *   120: conf_threshold_permille u16
 *   122: max_dist_permille u16
 *   124: track_history_k u8 / max_miss u8 / k_confirm u8 / flags u8
 *        (flags bit0 = tracks_report_enable, bit1 = heat_grid_enable)
 *   128: window_minutes u16 (pad 2)
 *   132: total_in u32, total_out u32, window_in u32, window_out u32
 *   148: report_seq u32
 *   152: (end; LC_ST_BLOB_SIZE = 152)
 */
#include "lc_stateblob.h"
#include "lc_bus_config.h"
#include "lc_app_abi_v2.h" /* lc_rd_u32 little-endian wire reader */
#include "lc_compat.h"

#define LC_ST_BLOB_SIZE 152u

static void wr_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t lc_crc32(const uint8_t *d, uint32_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < n; i++) {
        crc ^= d[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

uint32_t lc_st_encode(uint8_t *out, uint32_t cap, const lc_bus_config_t *cfg,
                      uint32_t total_in, uint32_t total_out,
                      uint32_t window_in, uint32_t window_out,
                      uint32_t report_seq)
{
    if (!out || !cfg || cap < LC_ST_BLOB_SIZE) return 0;
    lc_memset(out, 0, LC_ST_BLOB_SIZE);
    wr_u32(out + 0, LC_ST_BLOB_MAGIC);
    wr_u32(out + 4, LC_ST_BLOB_SCHEMA);

    lc_memcpy(out + 12, cfg->target_class_name, LC_TARGET_CLASS_NAME_LEN);
    lc_memcpy(out + 44, cfg->counter_name, LC_COUNTER_NAME_LEN);
    wr_u16(out + 108, cfg->line_x1_permille);
    wr_u16(out + 110, cfg->line_y1_permille);
    wr_u16(out + 112, cfg->line_x2_permille);
    wr_u16(out + 114, cfg->line_y2_permille);
    wr_u16(out + 116, cfg->outside_x_permille);
    wr_u16(out + 118, cfg->outside_y_permille);
    wr_u16(out + 120, cfg->conf_threshold_permille);
    wr_u16(out + 122, cfg->max_dist_permille);
    out[124] = cfg->track_history_k;
    out[125] = cfg->max_miss;
    out[126] = cfg->k_confirm;
    out[127] = (uint8_t)((cfg->tracks_report_enable ? 0x01u : 0u) |
                         (cfg->heat_grid_enable ? 0x02u : 0u));
    wr_u16(out + 128, cfg->window_minutes);
    wr_u32(out + 132, total_in);
    wr_u32(out + 136, total_out);
    wr_u32(out + 140, window_in);
    wr_u32(out + 144, window_out);
    wr_u32(out + 148, report_seq);

    wr_u32(out + 8, lc_crc32(out + 12, LC_ST_BLOB_SIZE - 12u));
    return LC_ST_BLOB_SIZE;
}

lc_st_status_t lc_st_decode(const uint8_t *in, uint32_t len,
                            lc_bus_config_t *cfg,
                            uint32_t *total_in, uint32_t *total_out,
                            uint32_t *window_in, uint32_t *window_out,
                            uint32_t *report_seq)
{
    if (!in || !cfg || len < LC_ST_BLOB_SIZE) return LC_ST_ERR_SIZE;
    if (lc_rd_u32(in + 0) != LC_ST_BLOB_MAGIC) return LC_ST_ERR_MAGIC;
    if (lc_rd_u32(in + 4) != LC_ST_BLOB_SCHEMA) return LC_ST_ERR_SCHEMA;
    uint32_t crc_stored = lc_rd_u32(in + 8);
    if (crc_stored != lc_crc32(in + 12, LC_ST_BLOB_SIZE - 12u)) return LC_ST_ERR_CRC;

    lc_memcpy(cfg->target_class_name, in + 12, LC_TARGET_CLASS_NAME_LEN);
    cfg->target_class_name[LC_TARGET_CLASS_NAME_LEN - 1u] = '\0';
    lc_memcpy(cfg->counter_name, in + 44, LC_COUNTER_NAME_LEN);
    cfg->counter_name[LC_COUNTER_NAME_LEN - 1u] = '\0';
    cfg->line_x1_permille = (uint16_t)(in[108] | ((uint16_t)in[109] << 8));
    cfg->line_y1_permille = (uint16_t)(in[110] | ((uint16_t)in[111] << 8));
    cfg->line_x2_permille = (uint16_t)(in[112] | ((uint16_t)in[113] << 8));
    cfg->line_y2_permille = (uint16_t)(in[114] | ((uint16_t)in[115] << 8));
    cfg->outside_x_permille = (uint16_t)(in[116] | ((uint16_t)in[117] << 8));
    cfg->outside_y_permille = (uint16_t)(in[118] | ((uint16_t)in[119] << 8));
    cfg->conf_threshold_permille = (uint16_t)(in[120] | ((uint16_t)in[121] << 8));
    cfg->max_dist_permille = (uint16_t)(in[122] | ((uint16_t)in[123] << 8));
    cfg->track_history_k = in[124];
    cfg->max_miss = in[125];
    cfg->k_confirm = in[126];
    cfg->tracks_report_enable = (uint8_t)(in[127] & 0x01u ? 1 : 0);
    cfg->heat_grid_enable = (uint8_t)(in[127] & 0x02u ? 1 : 0);
    cfg->window_minutes = (uint16_t)(in[128] | ((uint16_t)in[129] << 8));
    *total_in = lc_rd_u32(in + 132);
    *total_out = lc_rd_u32(in + 136);
    *window_in = lc_rd_u32(in + 140);
    *window_out = lc_rd_u32(in + 144);
    *report_seq = lc_rd_u32(in + 148);

    if (!lc_bus_config_valid(cfg)) return LC_ST_ERR_CONTENT;
    return LC_ST_OK;
}
