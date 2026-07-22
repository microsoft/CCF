// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tav/snp.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Buffer {
    uint8_t *data;
    size_t len;
} Buffer;

#define FIELD_WIDTH 36
#define SUBFIELD_INDENT 2
#define HEX_SECTION_BYTES 16
#define HEX_SECTIONS_PER_LINE 2

static Buffer read_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        exit(1);
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        exit(1);
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell");
        exit(1);
    }
    rewind(file);

    Buffer buffer = {
        .data = malloc((size_t)size),
        .len = (size_t)size,
    };
    if (buffer.data == NULL && buffer.len != 0) {
        perror("malloc");
        exit(1);
    }

    if (fread(buffer.data, 1, buffer.len, file) != buffer.len) {
        perror("fread");
        exit(1);
    }

    fclose(file);
    return buffer;
}

static void free_buffer(Buffer *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
}

static void print_field_prefix(const char *name) {
    printf("%-*s  ", FIELD_WIDTH, name);
}

static void print_subfield_prefix(const char *name) {
    printf("%*s%-*s  ", SUBFIELD_INDENT, "", FIELD_WIDTH - SUBFIELD_INDENT, name);
}

static void print_bytes(const char *name, const uint8_t *data, size_t len) {
    print_field_prefix(name);

    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);

        bool end_of_section = (i + 1) % HEX_SECTION_BYTES == 0;
        bool end_of_value = i + 1 == len;
        if (end_of_section && !end_of_value) {
            size_t section = (i + 1) / HEX_SECTION_BYTES;
            if (section % HEX_SECTIONS_PER_LINE == 0) {
                printf("\n%*s", FIELD_WIDTH + 2, "");
            } else {
                printf("  ");
            }
        }
    }

    printf("\n");
}

static void print_u8(const char *name, uint8_t value) {
    print_field_prefix(name);
    printf("%u\n", value);
}

static void print_u32(const char *name, uint32_t value) {
    print_field_prefix(name);
    printf("%u\n", value);
}

static void print_hex_u32(const char *name, uint32_t value) {
    print_field_prefix(name);
    printf("0x%08x\n", value);
}

static void print_hex_u64(const char *name, uint64_t value) {
    print_field_prefix(name);
    printf("0x%016llx\n", (unsigned long long)value);
}

static void print_subfield_u8(const char *name, uint8_t value) {
    print_subfield_prefix(name);
    printf("%u\n", value);
}

static void print_subfield_bool(const char *name, bool value) {
    print_subfield_prefix(name);
    printf("%s\n", value ? "true" : "false");
}

static void print_report(const TavSnpAttestationReport *report) {
    const uint8_t *data = NULL;
    size_t len = 0;

    print_u32("version", tav_snp_attestation_report_version(report));
    print_u32("guest_svn", tav_snp_attestation_report_guest_svn(report));
    print_hex_u64("policy", tav_snp_attestation_report_policy(report));
    print_subfield_u8("policy_abi_minor", tav_snp_attestation_report_policy_abi_minor(report));
    print_subfield_u8("policy_abi_major", tav_snp_attestation_report_policy_abi_major(report));
    print_subfield_bool("policy_smt", tav_snp_attestation_report_policy_smt(report));
    print_subfield_bool("policy_migrate_ma", tav_snp_attestation_report_policy_migrate_ma(report));
    print_subfield_bool("policy_debug", tav_snp_attestation_report_policy_debug(report));
    print_subfield_bool("policy_single_socket", tav_snp_attestation_report_policy_single_socket(report));
    print_subfield_bool("policy_cxl_allow", tav_snp_attestation_report_policy_cxl_allow(report));
    print_subfield_bool("policy_mem_aes_256_xts", tav_snp_attestation_report_policy_mem_aes_256_xts(report));
    print_subfield_bool("policy_rapl_dis", tav_snp_attestation_report_policy_rapl_dis(report));
    print_subfield_bool("policy_ciphertext_hiding_dram", tav_snp_attestation_report_policy_ciphertext_hiding_dram(report));
    print_subfield_bool("policy_page_swap_disable", tav_snp_attestation_report_policy_page_swap_disable(report));
    print_u32("vmpl", tav_snp_attestation_report_vmpl(report));
    print_u32("signature_algo", tav_snp_attestation_report_signature_algo(report));
    print_hex_u64("platform_info", tav_snp_attestation_report_platform_info(report));
    print_hex_u32("flags", tav_snp_attestation_report_flags(report));
    print_subfield_bool("flags_author_key_en", tav_snp_attestation_report_flags_author_key_en(report));
    print_subfield_bool("flags_mask_chip_key", tav_snp_attestation_report_flags_mask_chip_key(report));
    print_subfield_u8("flags_signing_key", tav_snp_attestation_report_flags_signing_key(report));
    print_u8("cpuid_fam_id", tav_snp_attestation_report_cpuid_fam_id(report));
    print_u8("cpuid_mod_id", tav_snp_attestation_report_cpuid_mod_id(report));
    print_u8("cpuid_step", tav_snp_attestation_report_cpuid_step(report));
    print_u8("current_build", tav_snp_attestation_report_current_build(report));
    print_u8("current_minor", tav_snp_attestation_report_current_minor(report));
    print_u8("current_major", tav_snp_attestation_report_current_major(report));
    print_u8("committed_build", tav_snp_attestation_report_committed_build(report));
    print_u8("committed_minor", tav_snp_attestation_report_committed_minor(report));
    print_u8("committed_major", tav_snp_attestation_report_committed_major(report));

#define PRINT_BYTES(field)                                      \
    do {                                                        \
        tav_snp_attestation_report_##field(report, &data, &len); \
        print_bytes(#field, data, len);                         \
    } while (0)

    PRINT_BYTES(family_id);
    PRINT_BYTES(image_id);
    PRINT_BYTES(platform_version);
    PRINT_BYTES(report_data);
    PRINT_BYTES(measurement);
    PRINT_BYTES(host_data);
    PRINT_BYTES(id_key_digest);
    PRINT_BYTES(author_key_digest);
    PRINT_BYTES(report_id);
    PRINT_BYTES(report_id_ma);
    PRINT_BYTES(reported_tcb);
    PRINT_BYTES(chip_id);
    PRINT_BYTES(committed_tcb);
    PRINT_BYTES(launch_tcb);
    PRINT_BYTES(signature_r);
    PRINT_BYTES(signature_s);

#undef PRINT_BYTES
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <attestation> <ark> <ask> <vcek>\n", argv[0]);
        return 1;
    }

    Buffer attestation = read_file(argv[1]);
    Buffer ark = read_file(argv[2]);
    Buffer ask = read_file(argv[3]);
    Buffer vcek = read_file(argv[4]);

    TavSnpAttestationReport *report = NULL;
    TavError *error = tav_verify_snp_attestation(
        attestation.data,
        attestation.len,
        ark.data,
        ark.len,
        ask.data,
        ask.len,
        vcek.data,
        vcek.len,
        &report);

    if (error != NULL) {
        TavErrorCode code = tav_error_code(error);
        fprintf(stderr, "%s\n", tav_error_message(error));
        tav_error_free(error);
        free_buffer(&attestation);
        free_buffer(&vcek);
        free_buffer(&ask);
        free_buffer(&ark);
        return (int)code;
    }

    print_report(report);

    tav_snp_attestation_report_free(report);
    free_buffer(&attestation);
    free_buffer(&vcek);
    free_buffer(&ask);
    free_buffer(&ark);
    return 0;
}
