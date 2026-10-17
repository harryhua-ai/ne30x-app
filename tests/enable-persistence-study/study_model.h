#ifndef ENABLE_PERSISTENCE_STUDY_MODEL_H
#define ENABLE_PERSISTENCE_STUDY_MODEL_H

#include "lc_bus.h"
#include "lc_stateblob.h"

#define STUDY_ENABLE_SCHEMA 3u
#define STUDY_ENABLE_BLOB_SIZE LC_ST_BLOB_SIZE_GEN
#define STUDY_ENABLE_FIELD_OFFSET 156u

typedef enum {
    STUDY_ENABLE_UNKNOWN = 0,
    STUDY_ENABLE_ENABLED = 1,
    STUDY_ENABLE_PAUSED = 2
} study_enable_t;

typedef enum {
    STUDY_RESULT_APPLIED = 0,
    STUDY_RESULT_ALREADY,
    STUDY_RESULT_CONFLICT,
    STUDY_RESULT_FAILED_IO,
    STUDY_RESULT_UNKNOWN,
    STUDY_RESULT_UNAUTHORIZED
} study_result_t;

typedef enum {
    STUDY_FAULT_NONE = 0,
    STUDY_FAULT_IO_BEFORE_WRITE,
    STUDY_FAULT_UNKNOWN_BEFORE_WRITE,
    STUDY_FAULT_UNKNOWN_AFTER_WRITE,
    STUDY_FAULT_TORN_WRITE
} study_fault_t;

typedef struct {
    lc_bus_config_t cfg;
    uint32_t total_in;
    uint32_t total_out;
    uint32_t window_in;
    uint32_t window_out;
    uint32_t report_seq;
    uint32_t config_generation;
    uint8_t source_schema;
    study_enable_t enable;
} study_record_t;

typedef struct {
    uint8_t blob[LC_ST_BLOB_MAX];
    uint32_t len;
    uint32_t revision;
    int present;
    study_fault_t next_fault;
} study_store_t;

typedef struct {
    study_record_t record;
    uint32_t revision;
    uint32_t window_start_ms;
    uint32_t report_queue_count;
    int tracker_active;
    int restricted;
} study_runtime_t;

void study_store_clear(study_store_t *store);
void study_store_seed(study_store_t *store, const uint8_t *blob,
                      uint32_t len, uint32_t revision);
uint32_t study_encode_schema3(uint8_t *out, uint32_t cap,
                              const study_record_t *record);
int study_decode_schema3(const uint8_t *blob, uint32_t len,
                         study_record_t *record);
study_result_t study_restore(const study_store_t *store,
                             study_runtime_t *runtime);
study_result_t study_migrate(study_store_t *store,
                             study_runtime_t *runtime);
study_result_t study_set_enable(study_store_t *store,
                                study_runtime_t *runtime,
                                study_enable_t requested,
                                uint32_t expected_revision,
                                uint32_t request_session,
                                uint32_t current_session,
                                uint32_t now_ms);
study_result_t study_readback(const study_store_t *store,
                              study_runtime_t *runtime);
int study_dispatch_frame(const study_runtime_t *runtime, lcbus_t *bus,
                         const uint8_t *event, uint32_t len);
int study_dispatch_idle(const study_runtime_t *runtime, lcbus_t *bus);

#endif
