#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_admission.h"
#include "mbedtls/sha256.h"

static int read_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long end;
    uint8_t *buf;

    if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (end = ftell(f)) <= 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        if (f != NULL) {
            fclose(f);
        }
        return -1;
    }
    buf = (uint8_t *)malloc((size_t)end);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1u, (size_t)end, f) != (size_t)end || fclose(f) != 0) {
        free(buf);
        return -1;
    }
    data[0] = buf;
    len[0] = (size_t)end;
    return 0;
}

static uint32_t parse_u32(const char *s)
{
    char *end;
    unsigned long value;

    errno = 0;
    value = strtoul(s, &end, 0);
    if (errno != 0 || *s == '\0' || *end != '\0' || value > 0xFFFFFFFFul) {
        return 0u;
    }
    return (uint32_t)value;
}

static void print_hex(const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0u; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static const char *result_category(app_admission_result_t result)
{
    switch (result) {
    case APP_ADMISSION_OK:
        return "PASS";
    case APP_ADMISSION_ERR_BAD_PACKAGE:
        return "BAD_PACKAGE";
    case APP_ADMISSION_ERR_SIGNATURE_INVALID:
        return "SIGNATURE_INVALID";
    case APP_ADMISSION_ERR_PUBLISHER_UNTRUSTED:
        return "PUBLISHER_UNTRUSTED";
    case APP_ADMISSION_ERR_TARGET_INCOMPATIBLE:
        return "TARGET_INCOMPATIBLE";
    case APP_ADMISSION_ERR_ABI_INCOMPATIBLE:
        return "ABI_INCOMPATIBLE";
    case APP_ADMISSION_ERR_RESOURCE_LIMIT:
        return "RESOURCE_LIMIT";
    case APP_ADMISSION_ERR_TRUST_UNPROVEN:
        return "TRUST_UNPROVEN";
    case APP_ADMISSION_ERR_PARAM:
    default:
        return "PARAM";
    }
}

int main(int argc, char **argv)
{
    uint8_t *package = NULL;
    uint8_t *spki = NULL;
    size_t package_len = 0u;
    size_t spki_len = 0u;
    uint8_t package_sha[APP_ADMISSION_SHA256_LEN];
    app_admission_policy_t policy;
    app_admission_trust_view_t trust;
    app_admission_verdict_t verdict;
    app_admission_result_t result;
    uint32_t supported_caps;
    uint32_t exec_region_size;

    if (argc != 7) {
        fprintf(stderr, "usage: joint_host_parser CASE PACKAGE PUBLISHER SPKI CAPS EXEC_REGION_SIZE\n");
        return 2;
    }
    if (read_file(argv[2], &package, &package_len) != 0 ||
        read_file(argv[4], &spki, &spki_len) != 0) {
        fprintf(stderr, "cannot read package or SPKI\n");
        free(package);
        free(spki);
        return 2;
    }
    supported_caps = parse_u32(argv[5]);
    exec_region_size = parse_u32(argv[6]);
    if (supported_caps == 0u || exec_region_size == 0u) {
        fprintf(stderr, "invalid policy argument\n");
        free(package);
        free(spki);
        return 2;
    }

    memset(&policy, 0, sizeof(policy));
    policy.target_board_id = APP_ADMISSION_EXPERIMENT_BOARD_ID;
    policy.psram_mib = 64u;
    policy.abi_version = APP_ADMISSION_ABI_VERSION_V4;
    policy.abi_table_size = APP_ADMISSION_V4_ABI_TABLE_SIZE;
    policy.supported_caps_mask = supported_caps;
    policy.exec_region_base = 0x93E00000u;
    policy.exec_region_size = exec_region_size;
    policy.max_package_len = APP_ADMISSION_MAX_PACKAGE_LEN_V4;
    policy.event_capacity = 8192u;
    policy.report_capacity = 8192u;
    policy.state_quota_capacity = 8192u;
    policy.control_capacity = 1024u;
    policy.snapshot_capacity = 4096u;
    policy.live_publish_capacity = 9008u;
    policy.live_track_capacity = 64u;
    policy.v3_business_profile = APP_ADMISSION_V3_BUSINESS_GENERIC_FULL;
    trust.publisher_id = argv[3];
    trust.publisher_id_len = strlen(argv[3]);
    trust.spki_der = spki;
    trust.spki_der_len = spki_len;

    memset(&verdict, 0, sizeof(verdict));
    result = app_admission_verify_package(package, package_len, &policy, &trust, &verdict);
    mbedtls_sha256(package, package_len, package_sha, 0);
    printf("HOST_C case=%s result=%s raw=%s package_sha256=", argv[1],
           result_category(result), app_admission_result_str(result));
    print_hex(package_sha, sizeof(package_sha));
    if (result == APP_ADMISSION_OK) {
        printf(" publisher=%s caps=0x%08x tbs_sha256=", verdict.publisher_id,
               (unsigned int)verdict.required_host_caps);
        print_hex(verdict.tbs_sha256, sizeof(verdict.tbs_sha256));
        printf(" image_sha256=");
        print_hex(verdict.image_sha256, sizeof(verdict.image_sha256));
        printf(" spki_sha256=");
        print_hex(verdict.publisher_key_sha256, sizeof(verdict.publisher_key_sha256));
    }
    printf("\n");
    free(package);
    free(spki);
    return 0;
}
