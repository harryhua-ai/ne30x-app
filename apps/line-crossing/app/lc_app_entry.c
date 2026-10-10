/*
 * lc_app_entry.c — app_entry for the Line Crossing App (Host ABI v2).
 *
 * This file is the ONLY place that touches the raw lc_app_api_v2_t table.
 * It (1) validates the entry contract, (2) exposes the lcbus_host_ops
 * adapter over that table for the business layer, and (3) runs the
 * cooperative event loop:
 *
 *   event_next -> strict wire validation -> business dispatch
 *   should_stop / STOPPING -> final state_commit -> return
 *
 * Run loop invariants: every wait is bounded (max_wait_ms); NO_EVENT,
 * empty FRAME, MODEL_CHANGED, GAP and STOPPING keep distinct observable
 * semantics; tick differences are always modulo 2^32 (§6.3 tick_ms
 * exception); any UNAUTHORIZED ends the session after a best-effort final
 * state commit; persistent host contract violations end with a distinct
 * exit code instead of being absorbed.
 */
#include "lc_app_entry.h"
#include "lc_bus.h"
#include "lc_arena.h"
#include "lc_compat.h"

/* ---- the ABI adapter (user = const lc_app_api_v2_t *) -------------------- */

static int32_t op_model_meta(void *user, uint8_t *out128)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    uint32_t alen = 0;
    int32_t r = api->model_meta(out128, LC_MODEL_META_SIZE, &alen);
    if (r == LC_RET_OK && alen != LC_MODEL_META_SIZE) {
        return LC_RET_INVALID_ARGUMENT; /* fixed-size wire: length is contractual */
    }
    return r;
}

static int32_t op_class_name(void *user, uint32_t model_gen, uint32_t class_gen,
                             uint32_t class_index, char *out_utf8, uint32_t cap,
                             uint32_t *actual_len)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    return api->class_name(model_gen, class_gen, class_index, out_utf8, cap, actual_len);
}

static uint32_t op_tick_ms(void *user)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    /* §6.3 exception: raw 32-bit monotonic-ms bit pattern, mod-2^32 math only */
    return (uint32_t)api->tick_ms();
}

static int32_t op_state_read(void *user, uint8_t *out, uint32_t cap,
                             uint32_t *actual_len, uint32_t *out_revision)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    return api->state_read(out, cap, actual_len, out_revision);
}

static int32_t op_state_commit(void *user, const uint8_t *blob, uint32_t len,
                               uint32_t expected_revision, uint32_t *new_revision)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    return api->state_commit(blob, len, expected_revision, new_revision);
}

static int32_t op_report_submit(void *user, const uint8_t *json, uint32_t len,
                                uint32_t app_report_seq, uint32_t *out_host_boot_id)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    return api->report_submit(json, len, app_report_seq, out_host_boot_id);
}

static int32_t op_report_status(void *user, uint32_t host_boot_id, uint32_t report_seq,
                                uint32_t *out_mqtt_state, uint32_t *out_webhook_state)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    return api->report_status(host_boot_id, report_seq, out_mqtt_state, out_webhook_state);
}

static void op_log(void *user, const char *text)
{
    const lc_app_api_v2_t *api = (const lc_app_api_v2_t *)user;
    (void)api->log(text);
}

const lcbus_host_ops_t *lcbus_abi_ops(void)
{
    static const lcbus_host_ops_t ops = {
        NULL,
        op_model_meta,
        op_class_name,
        op_tick_ms,
        op_state_read,
        op_state_commit,
        op_report_submit,
        op_report_status,
        op_log
    };
    return &ops;
}

/* ---- session state (all zero-initialized .bss; no .data anywhere) --------- */

static lcbus_t  lc_app_bus;
static uint8_t  lc_app_event_buf[LC_APP_EVENT_BUF_CAP];

/* ---- entry ----------------------------------------------------------------- */

int32_t app_entry(const lc_app_api_v2_t *api, uint32_t abi_version)
{
    if (api == NULL) return LC_APP_EXIT_BAD_API;
    if (api->table_size != LC_APP_API_TABLE_SIZE) return LC_APP_EXIT_BAD_TABLE;
    if (abi_version != LC_APP_ABI_V2) return LC_APP_EXIT_BAD_ABI;
    if (!api->log || !api->tick_ms || !api->event_next || !api->model_meta ||
        !api->class_name || !api->report_submit || !api->report_status ||
        !api->state_read || !api->state_commit || !api->should_stop) {
        return LC_APP_EXIT_BAD_FNPTR;
    }

    op_log((void *)api, "line-crossing-app " LC_APP_SW_VERSION ": v2 session entry");

    lcapp_arena_init();
    lcbus_host_ops_t ops = *lcbus_abi_ops();
    ops.user = (void *)api;
    lcbus_init(&lc_app_bus, &ops);
    lcbus_restore(&lc_app_bus);
    if (lc_app_bus.session_fatal) {
        op_log((void *)api, "line-crossing-app: session not authorized");
        return LC_APP_EXIT_UNAUTHORIZED;
    }
    lcbus_rebind(&lc_app_bus, 1);

    int32_t exit_code = LC_APP_EXIT_OK;
    uint32_t consecutive_faults = 0;
    uint32_t iterations = 0;

    for (;;) {
        int32_t stop = api->should_stop();
        if (stop == 1) {
            op_log((void *)api, "line-crossing-app: host requested stop");
            break;
        }
        if (stop < 0) {
            /* §6.8: negative = invalid/error — counted, never treated as stop.
             * Only a successfully consumed event clears the fault streak;
             * NO_EVENT is not evidence that the Host recovered. */
            lc_app_bus.st.host_faults++;
            if (++consecutive_faults >= 3u) {
                exit_code = LC_APP_EXIT_HOST_FAULT;
                break;
            }
        }

        uint32_t alen = 0;
        int32_t r = api->event_next(lc_app_event_buf, (uint32_t)sizeof(lc_app_event_buf),
                                    &alen, 1000u);
        if (r == LC_RET_OK) {
            consecutive_faults = 0;
            if (alen > (uint32_t)sizeof(lc_app_event_buf)) {
                lc_app_bus.st.host_faults++;
                if (++consecutive_faults >= 3u) { exit_code = LC_APP_EXIT_HOST_FAULT; break; }
                continue;
            }
            lcbus_on_event(&lc_app_bus, lc_app_event_buf, alen);
        } else if (r == LC_RET_NO_EVENT) {
            lcbus_on_idle(&lc_app_bus);
        } else if (r == LC_RET_STOPPING) {
            op_log((void *)api, "line-crossing-app: event channel STOPPING");
            break;
        } else if (r == LC_RET_UNAUTHORIZED) {
            lc_app_bus.session_fatal = 1;
        } else {
            /* NOT_FOUND / INVALID_ARGUMENT / BUFFER_TOO_SMALL / ... on the
             * event channel are host contract breaches: bounded retries */
            lc_app_bus.st.host_faults++;
            if (++consecutive_faults >= 3u) { exit_code = LC_APP_EXIT_HOST_FAULT; break; }
            lcbus_on_idle(&lc_app_bus);
        }

        if (lc_app_bus.session_fatal) {
            exit_code = LC_APP_EXIT_UNAUTHORIZED;
            break;
        }
        if (lc_app_bus.stop_requested) {
            op_log((void *)api, "line-crossing-app: STOPPING event received");
            break;
        }
        if (lc_app_bus.resource_fatal) {
            exit_code = LC_APP_EXIT_RESOURCES;
            break;
        }
        if (++iterations > 1000000u) {   /* runaway guard (also bounds tests) */
            exit_code = LC_APP_EXIT_HOST_FAULT;
            break;
        }
    }

    /* best-effort final commit so the exit is not a silent state loss */
    lcbus_flush(&lc_app_bus, 1);
    op_log((void *)api, "line-crossing-app: session end");
    return exit_code;
}
