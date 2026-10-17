#include "study_model.h"

#include <string.h>

static uint32_t rd_u32(const uint8_t *p)
{
    return lc_rd_u32(p);
}

static void wr_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint32_t study_crc32(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

void study_store_clear(study_store_t *store)
{
    memset(store, 0, sizeof(*store));
}

void study_store_seed(study_store_t *store, const uint8_t *blob,
                      uint32_t len, uint32_t revision)
{
    if (len > sizeof(store->blob)) return;
    memset(store, 0, sizeof(*store));
    if (blob != NULL && len != 0u) {
        memcpy(store->blob, blob, len);
        store->len = len;
        store->revision = revision;
        store->present = 1;
    }
}

uint32_t study_encode_schema3(uint8_t *out, uint32_t cap,
                              const study_record_t *record)
{
    uint32_t len;
    if (out == NULL || record == NULL ||
        (record->enable != STUDY_ENABLE_ENABLED &&
         record->enable != STUDY_ENABLE_PAUSED)) return 0u;
    len = lc_st_encode_gen(out, cap, &record->cfg, record->total_in,
                           record->total_out, record->window_in,
                           record->window_out, record->report_seq,
                           record->config_generation);
    if (len != STUDY_ENABLE_BLOB_SIZE) return 0u;
    wr_u32(out + 4, STUDY_ENABLE_SCHEMA);
    wr_u32(out + STUDY_ENABLE_FIELD_OFFSET, (uint32_t)record->enable);
    wr_u32(out + 8, study_crc32(out + 12, len - 12u));
    return len;
}

int study_decode_schema3(const uint8_t *blob, uint32_t len,
                         study_record_t *record)
{
    uint8_t compatible[STUDY_ENABLE_BLOB_SIZE];
    uint32_t enabled;
    uint32_t generation = 0u;
    if (blob == NULL || record == NULL || len != STUDY_ENABLE_BLOB_SIZE ||
        rd_u32(blob) != LC_ST_BLOB_MAGIC ||
        rd_u32(blob + 4) != STUDY_ENABLE_SCHEMA ||
        rd_u32(blob + 8) != study_crc32(blob + 12, len - 12u)) return 0;
    enabled = rd_u32(blob + STUDY_ENABLE_FIELD_OFFSET);
    if (enabled != STUDY_ENABLE_ENABLED && enabled != STUDY_ENABLE_PAUSED) return 0;
    memcpy(compatible, blob, sizeof(compatible));
    wr_u32(compatible + 4, LC_ST_BLOB_SCHEMA_GEN);
    memset(record, 0, sizeof(*record));
    if (lc_st_decode_gen(compatible, sizeof(compatible), &record->cfg,
                         &record->total_in, &record->total_out,
                         &record->window_in, &record->window_out,
                         &record->report_seq, &generation) != LC_ST_OK) return 0;
    record->config_generation = generation;
    record->source_schema = STUDY_ENABLE_SCHEMA;
    record->enable = (study_enable_t)enabled;
    return 1;
}

static int decode_record(const uint8_t *blob, uint32_t len,
                         study_record_t *record)
{
    uint32_t generation = 1u;
    lc_st_status_t status;
    memset(record, 0, sizeof(*record));
    if (len >= 8u && rd_u32(blob + 4) == STUDY_ENABLE_SCHEMA) {
        return study_decode_schema3(blob, len, record);
    }
    if (len >= 8u && rd_u32(blob + 4) == LC_ST_BLOB_SCHEMA_GEN) {
        status = lc_st_decode_gen(blob, len, &record->cfg,
                                  &record->total_in, &record->total_out,
                                  &record->window_in, &record->window_out,
                                  &record->report_seq, &generation);
        if (status != LC_ST_OK) return 0;
        record->config_generation = generation;
        record->source_schema = LC_ST_BLOB_SCHEMA_GEN;
    } else {
        status = lc_st_decode(blob, len, &record->cfg,
                              &record->total_in, &record->total_out,
                              &record->window_in, &record->window_out,
                              &record->report_seq);
        if (status != LC_ST_OK) return 0;
        record->config_generation = 1u;
        record->source_schema = LC_ST_BLOB_SCHEMA;
    }
    record->enable = STUDY_ENABLE_ENABLED;
    return 1;
}

study_result_t study_restore(const study_store_t *store,
                             study_runtime_t *runtime)
{
    uint32_t queue_count = runtime->report_queue_count;
    memset(runtime, 0, sizeof(*runtime));
    runtime->report_queue_count = queue_count;
    if (store == NULL || !store->present) {
        lc_bus_config_defaults(&runtime->record.cfg);
        runtime->record.config_generation = 1u;
        runtime->record.enable = STUDY_ENABLE_ENABLED;
        return STUDY_RESULT_APPLIED;
    }
    runtime->revision = store->revision;
    if (!decode_record(store->blob, store->len, &runtime->record)) {
        runtime->record.enable = STUDY_ENABLE_UNKNOWN;
        runtime->restricted = 1;
        return STUDY_RESULT_UNKNOWN;
    }
    return STUDY_RESULT_APPLIED;
}

static int store_commit(study_store_t *store, const uint8_t *blob,
                        uint32_t len, uint32_t expected_revision,
                        uint32_t *new_revision)
{
    uint32_t current_revision = store->present ? store->revision : 0u;
    study_fault_t fault = store->next_fault;
    store->next_fault = STUDY_FAULT_NONE;
    if (expected_revision != current_revision) return LC_RET_REVISION_CONFLICT;
    if (fault == STUDY_FAULT_IO_BEFORE_WRITE) return LC_RET_IO_ERROR;
    if (fault == STUDY_FAULT_UNKNOWN_BEFORE_WRITE) return LC_RET_STORAGE_UNKNOWN;
    if (fault == STUDY_FAULT_TORN_WRITE) {
        uint32_t partial = len / 2u;
        if (partial > sizeof(store->blob)) partial = sizeof(store->blob);
        memcpy(store->blob, blob, partial);
        store->len = len;
        store->revision = current_revision + 1u;
        store->present = 1;
        return LC_RET_STORAGE_UNKNOWN;
    }
    if (len > sizeof(store->blob)) return LC_RET_QUOTA_EXCEEDED;
    memcpy(store->blob, blob, len);
    store->len = len;
    store->revision = current_revision + 1u;
    store->present = 1;
    *new_revision = store->revision;
    return (fault == STUDY_FAULT_UNKNOWN_AFTER_WRITE)
               ? LC_RET_STORAGE_UNKNOWN : LC_RET_OK;
}

static study_result_t persist_record(study_store_t *store,
                                     study_runtime_t *runtime,
                                     study_record_t *record,
                                     uint32_t expected_revision)
{
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len = study_encode_schema3(blob, sizeof(blob), record);
    uint32_t new_revision = 0u;
    int result;
    if (len == 0u) return STUDY_RESULT_UNKNOWN;
    result = store_commit(store, blob, len, expected_revision, &new_revision);
    if (result == LC_RET_OK) {
        record->source_schema = STUDY_ENABLE_SCHEMA;
        runtime->record = *record;
        runtime->revision = new_revision;
        runtime->restricted = 0;
        return STUDY_RESULT_APPLIED;
    }
    if (result == LC_RET_IO_ERROR) return STUDY_RESULT_FAILED_IO;
    if (result == LC_RET_REVISION_CONFLICT) return STUDY_RESULT_CONFLICT;
    runtime->record.enable = STUDY_ENABLE_UNKNOWN;
    runtime->restricted = 1;
    return STUDY_RESULT_UNKNOWN;
}

study_result_t study_migrate(study_store_t *store,
                             study_runtime_t *runtime)
{
    study_record_t record;
    if (runtime->restricted || runtime->record.enable == STUDY_ENABLE_UNKNOWN)
        return STUDY_RESULT_UNKNOWN;
    if (runtime->record.source_schema == STUDY_ENABLE_SCHEMA)
        return STUDY_RESULT_ALREADY;
    if (runtime->record.source_schema == 0u)
        return STUDY_RESULT_FAILED_IO;
    record = runtime->record;
    record.enable = STUDY_ENABLE_ENABLED;
    record.source_schema = STUDY_ENABLE_SCHEMA;
    if (record.config_generation == 0u) record.config_generation = 1u;
    return persist_record(store, runtime, &record, runtime->revision);
}

study_result_t study_set_enable(study_store_t *store,
                                study_runtime_t *runtime,
                                study_enable_t requested,
                                uint32_t expected_revision,
                                uint32_t request_session,
                                uint32_t current_session,
                                uint32_t now_ms)
{
    study_record_t record;
    if (request_session == 0u || request_session != current_session)
        return STUDY_RESULT_UNAUTHORIZED;
    if (runtime->restricted || runtime->record.enable == STUDY_ENABLE_UNKNOWN ||
        (requested != STUDY_ENABLE_ENABLED && requested != STUDY_ENABLE_PAUSED))
        return STUDY_RESULT_UNKNOWN;
    if (expected_revision != runtime->revision || store->revision != expected_revision)
        return STUDY_RESULT_CONFLICT;
    if (runtime->record.enable == requested) return STUDY_RESULT_ALREADY;
    if (store->present) {
        if (!decode_record(store->blob, store->len, &record)) {
            runtime->record.enable = STUDY_ENABLE_UNKNOWN;
            runtime->restricted = 1;
            return STUDY_RESULT_UNKNOWN;
        }
    } else {
        record = runtime->record;
    }
    record.enable = requested;
    record.window_in = 0u;
    record.window_out = 0u;
    record.source_schema = STUDY_ENABLE_SCHEMA;
    if (record.config_generation == 0u) record.config_generation = 1u;
    study_result_t result = persist_record(store, runtime, &record, expected_revision);
    if (result == STUDY_RESULT_APPLIED) {
        runtime->window_start_ms = now_ms;
        runtime->tracker_active = 0;
    }
    return result;
}

study_result_t study_readback(const study_store_t *store,
                              study_runtime_t *runtime)
{
    return study_restore(store, runtime);
}

int study_dispatch_frame(const study_runtime_t *runtime, lcbus_t *bus,
                         const uint8_t *event, uint32_t len)
{
    if (runtime->restricted || runtime->record.enable != STUDY_ENABLE_ENABLED)
        return 0;
    lcbus_on_event(bus, event, len);
    return 1;
}

int study_dispatch_idle(const study_runtime_t *runtime, lcbus_t *bus)
{
    if (runtime->restricted || runtime->record.enable != STUDY_ENABLE_ENABLED)
        return 0;
    lcbus_on_idle(bus);
    return 1;
}
