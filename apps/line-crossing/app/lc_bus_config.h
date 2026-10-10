/*
 * lc_bus_config.h — the Line Crossing App business configuration.
 *
 * Field-for-field parity with the frozen counting business configuration
 * (ne301 counting@de25a6f1 Custom/Core/System/line_counting_config.{h,c},
 * line_counting_config_t): same defaults, same validation ranges, same
 * "counter name is an editable label" principle.  Deliberately dropped:
 * enable (a started v2 session IS the enable), mqtt/webhook_report_enable
 * and backlog_capacity (transport and queueing are Host-owned, spec §6.6),
 * model_name/model_pp_type (Host-selected model, §5/§6.5).
 */
#ifndef LC_BUS_CONFIG_H
#define LC_BUS_CONFIG_H

#include <stdint.h>

#define LC_COUNTER_NAME_LEN      64  /* counting parity (incl. NUL) */
#define LC_TARGET_CLASS_NAME_LEN 32  /* counting parity; v2 spec §5.4   */

typedef struct lc_bus_config {
    char     counter_name[LC_COUNTER_NAME_LEN];
    char     target_class_name[LC_TARGET_CLASS_NAME_LEN];
    uint16_t line_x1_permille, line_y1_permille;
    uint16_t line_x2_permille, line_y2_permille;
    uint16_t outside_x_permille, outside_y_permille;
    uint16_t conf_threshold_permille;
    uint16_t max_dist_permille;
    uint8_t  track_history_k;
    uint8_t  max_miss;
    uint8_t  k_confirm;
    uint16_t window_minutes;
    uint8_t  tracks_report_enable;
    uint8_t  heat_grid_enable;
} lc_bus_config_t;

void lc_bus_config_defaults(lc_bus_config_t *cfg);
int  lc_bus_config_valid(const lc_bus_config_t *cfg);
/* strict UTF-8 validation (same rules as counting's
 * line_counting_config_utf8_valid) */
int  lc_bus_utf8_valid(const char *s);

#endif
