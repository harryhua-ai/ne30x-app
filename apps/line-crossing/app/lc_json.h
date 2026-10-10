/*
 * lc_json.h — minimal overflow-detecting JSON writer (no libc).
 *
 * Used to build the schema_version=1 / type=line_counting business report.
 * Once the capacity is exceeded the writer latches lcj->overflow and emits
 * nothing further; the report builder MUST then drop the whole report
 * (v2 spec §4.1: no truncation of submitted reports, ever).
 */
#ifndef LC_JSON_H
#define LC_JSON_H

#include <stddef.h>
#include <stdint.h>

typedef struct lc_json {
    char    *buf;
    uint32_t cap;
    uint32_t len;
    uint8_t  overflow;
} lc_json_t;

void lcj_init(lc_json_t *j, char *buf, uint32_t cap);
void lcj_raw(lc_json_t *j, const char *s);          /* pre-formed fragment   */
void lcj_string(lc_json_t *j, const char *s);       /* quoted + escaped      */
void lcj_u32(lc_json_t *j, uint32_t v);
void lcj_i32(lc_json_t *j, int32_t v);
void lcj_bool(lc_json_t *j, int v);
void lcj_null(lc_json_t *j);
/* permille-sourced float: exact v/1000 printed as 0.ddd / 1.000 style */
void lcj_permille(lc_json_t *j, uint32_t permille);
/* arbitrary binary32 (normalized coordinates); 6 decimals, clamped to [0,2) */
void lcj_coord(lc_json_t *j, float v);

#endif
