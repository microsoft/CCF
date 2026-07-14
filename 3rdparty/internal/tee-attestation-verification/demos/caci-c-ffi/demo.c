// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tav/caci.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Input layout sizes documented by ffi/include/tav/caci.h: each trusted policy
// digest is a 32-byte SNP HOST_DATA value and each minimum-TCB value is an
// 8-byte SNP TCB_VERSION.
enum {
    SNP_HOST_DATA_LEN = 32,
    SNP_TCB_VERSION_LEN = 8,
};

typedef struct Buffer {
    uint8_t *data;
    size_t len;
} Buffer;

typedef struct OwnedString {
    char *data;
    size_t len;
} OwnedString;

static void die(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

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

static void free_string(OwnedString *string) {
    free(string->data);
    string->data = NULL;
    string->len = 0;
}

static OwnedString string_from_range(const char *start, const char *end) {
    if (end < start) {
        die("invalid string range");
    }
    size_t len = (size_t)(end - start);
    OwnedString out = {
        .data = malloc(len + 1),
        .len = len,
    };
    if (out.data == NULL) {
        perror("malloc");
        exit(1);
    }
    memcpy(out.data, start, len);
    out.data[len] = '\0';
    return out;
}

static int hex_nibble(uint8_t ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static Buffer decode_hex(const uint8_t *text, size_t len, const char *name) {
    size_t digits = 0;
    for (size_t i = 0; i < len; i++) {
        if (isspace(text[i])) {
            continue;
        }
        if (hex_nibble(text[i]) < 0) {
            fprintf(stderr, "%s contains a non-hex character\n", name);
            exit(1);
        }
        digits++;
    }
    if (digits % 2 != 0) {
        fprintf(stderr, "%s must contain an even number of hex digits\n", name);
        exit(1);
    }

    Buffer out = {
        .data = malloc(digits / 2),
        .len = digits / 2,
    };
    if (out.data == NULL && out.len != 0) {
        perror("malloc");
        exit(1);
    }

    int high = -1;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (isspace(text[i])) {
            continue;
        }
        int nibble = hex_nibble(text[i]);
        if (high < 0) {
            high = nibble;
        } else {
            out.data[j++] = (uint8_t)((high << 4) | nibble);
            high = -1;
        }
    }
    return out;
}

static int base64_value(uint8_t ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    return -1;
}

static Buffer decode_base64(const uint8_t *text, size_t len, const char *name) {
    Buffer out = {
        .data = malloc((len / 4 + 1) * 3),
        .len = 0,
    };
    if (out.data == NULL) {
        perror("malloc");
        exit(1);
    }

    unsigned int accumulator = 0;
    int bits = -8;
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = text[i];
        if (isspace(ch)) {
            continue;
        }
        if (ch == '=') {
            break;
        }
        int value = base64_value(ch);
        if (value < 0) {
            fprintf(stderr, "%s contains a non-base64 character\n", name);
            exit(1);
        }
        accumulator = (accumulator << 6) | (unsigned int)value;
        bits += 6;
        if (bits >= 0) {
            out.data[out.len++] = (uint8_t)((accumulator >> bits) & 0xff);
            bits -= 8;
        }
    }
    return out;
}

static OwnedString buffer_to_c_string(Buffer buffer, const char *name) {
    if (memchr(buffer.data, '\0', buffer.len) != NULL) {
        fprintf(stderr, "%s contains a NUL byte\n", name);
        exit(1);
    }
    OwnedString out = {
        .data = malloc(buffer.len + 1),
        .len = buffer.len,
    };
    if (out.data == NULL) {
        perror("malloc");
        exit(1);
    }
    memcpy(out.data, buffer.data, buffer.len);
    out.data[buffer.len] = '\0';
    return out;
}

static const char *skip_ws(const char *p) {
    while (isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static OwnedString json_string_value(const char *json, const char *key) {
    char pattern[128];
    int pattern_len = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (pattern_len < 0 || (size_t)pattern_len >= sizeof(pattern)) {
        die("JSON key is too long");
    }

    const char *p = strstr(json, pattern);
    if (p == NULL) {
        fprintf(stderr, "host AMD certificate JSON missing %s\n", key);
        exit(1);
    }
    p = skip_ws(p + pattern_len);
    if (*p != ':') {
        fprintf(stderr, "host AMD certificate JSON key %s is missing ':'\n", key);
        exit(1);
    }
    p = skip_ws(p + 1);
    if (*p != '"') {
        fprintf(stderr, "host AMD certificate JSON key %s is not a string\n", key);
        exit(1);
    }
    p++;

    size_t capacity = strlen(p) + 1;
    OwnedString out = {
        .data = malloc(capacity),
        .len = 0,
    };
    if (out.data == NULL) {
        perror("malloc");
        exit(1);
    }

    while (*p != '\0') {
        char ch = *p++;
        if (ch == '"') {
            out.data[out.len] = '\0';
            return out;
        }
        if (ch != '\\') {
            out.data[out.len++] = ch;
            continue;
        }

        char escaped = *p++;
        switch (escaped) {
            case 'n':
                out.data[out.len++] = '\n';
                break;
            case 'r':
                out.data[out.len++] = '\r';
                break;
            case 't':
                out.data[out.len++] = '\t';
                break;
            case '"':
            case '\\':
            case '/':
                out.data[out.len++] = escaped;
                break;
            default:
                fprintf(stderr, "unsupported JSON escape in %s\n", key);
                exit(1);
        }
    }

    fprintf(stderr, "host AMD certificate JSON key %s is unterminated\n", key);
    exit(1);
}

static void split_pem_chain(const char *chain, OwnedString *ask, OwnedString *ark) {
    static const char begin_marker[] = "-----BEGIN CERTIFICATE-----";
    static const char end_marker[] = "-----END CERTIFICATE-----";

    const char *ask_begin = strstr(chain, begin_marker);
    if (ask_begin == NULL) {
        die("certificateChain missing ASK certificate");
    }
    const char *ask_end = strstr(ask_begin, end_marker);
    if (ask_end == NULL) {
        die("certificateChain ASK certificate is unterminated");
    }
    ask_end += strlen(end_marker);
    if (*ask_end == '\n') {
        ask_end++;
    }

    const char *ark_begin = strstr(ask_end, begin_marker);
    if (ark_begin == NULL) {
        die("certificateChain missing ARK certificate");
    }
    const char *ark_end = strstr(ark_begin, end_marker);
    if (ark_end == NULL) {
        die("certificateChain ARK certificate is unterminated");
    }
    ark_end += strlen(end_marker);
    if (*ark_end == '\n') {
        ark_end++;
    }

    *ask = string_from_range(ask_begin, ask_end);
    *ark = string_from_range(ark_begin, ark_end);
}

static int consume_snp_error(TavError *error, const char *context) {
    if (error == NULL) {
        return 0;
    }

    TavErrorCode code = tav_error_code(error);
    fprintf(stderr, "%s: %s\n", context, tav_error_message(error));
    tav_error_free(error);
    return code == TAV_ERROR_OK ? 1 : (int)code;
}

static int consume_caci_error(TavError *error, const char *context) {
    if (error == NULL) {
        return 0;
    }

    TavErrorCode code = tav_error_code(error);
    fprintf(stderr, "%s (code %d): %s\n", context, (int)code, tav_error_message(error));
    tav_error_free(error);
    return 1;
}

static void check_cose_error(TavError *error, const char *context) {
    if (error == NULL) {
        return;
    }

    fprintf(stderr, "%s: %s\n", context, tav_error_message(error));
    tav_error_free(error);
    exit(1);
}

static void print_hex_lines(const uint8_t *data, size_t len, size_t indent) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i != 0) {
                printf("\n");
            }
            for (size_t j = 0; j < indent; j++) {
                printf(" ");
            }
        }
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_text_value(const char *label, const char *text, size_t len) {
    printf("  %s: ", label);
    fwrite(text, 1, len, stdout);
    printf("\n");
}

static void print_borrowed_report_field(
    const char *name,
    void (*accessor)(const TavSnpAttestationReport *, const uint8_t **, size_t *),
    const TavSnpAttestationReport *report) {
    const uint8_t *data = NULL;
    size_t len = 0;
    accessor(report, &data, &len);

    printf("  %s\n", name);
    print_hex_lines(data, len, 4);
}

static void print_uvm_endorsement(const TavCborValue *uvm_endorsement) {
    const TavCborValue *sign1 = NULL;
    const TavCborValue *protected_value = NULL;
    const uint8_t *protected_bytes = NULL;
    size_t protected_len = 0;
    TavCborValue *protected_header = NULL;
    const TavCborValue *content_type = NULL;
    const TavCborValue *feed = NULL;
    const char *text = NULL;
    size_t text_len = 0;

    check_cose_error(
        tav_validate_cose_sign1(uvm_endorsement, &sign1),
        "validate returned UVM COSE_Sign1");
    check_cose_error(
        tav_cbor_value_array_at(sign1, TAV_COSE_SIGN1_PROTECTED, &protected_value),
        "read UVM protected header bytes");
    check_cose_error(
        tav_cbor_value_bytes(protected_value, &protected_bytes, &protected_len),
        "borrow UVM protected header bytes");
    check_cose_error(
        tav_cbor_value_from_bytes(protected_bytes, protected_len, &protected_header),
        "parse UVM protected header");

    check_cose_error(
        tav_cbor_value_map_at_int(protected_header, TAV_COSE_HEADER_CONTENT_TYPE, &content_type),
        "read UVM content type");
    check_cose_error(tav_cbor_value_text(content_type, &text, &text_len), "read UVM content type text");
    print_text_value("content_type", text, text_len);

    check_cose_error(
        tav_cbor_value_map_at_text(protected_header, "feed", strlen("feed"), &feed),
        "read UVM feed");
    check_cose_error(tav_cbor_value_text(feed, &text, &text_len), "read UVM feed text");
    print_text_value("feed", text, text_len);

    tav_cbor_value_free(protected_header);
}

static uint64_t parse_u64(const char *text, const char *name) {
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "%s must be an unsigned integer\n", name);
        exit(1);
    }
    return (uint64_t)value;
}

static void print_minimum_tcb(
    const uint32_t *cpuids,
    const uint8_t *values,
    size_t count) {
    printf("minimum_tcb\n");
    for (size_t i = 0; i < count; i++) {
        printf("  cpuid: 0x%08x\n", cpuids[i]);
        printf("  tcb\n");
        print_hex_lines(values + i * SNP_TCB_VERSION_LEN, SNP_TCB_VERSION_LEN, 4);
    }
}

int main(int argc, char **argv) {
    if (argc != 8) {
        fprintf(
            stderr,
            "usage: %s <report.hex> <host-amd-cert.base64> <uvm.base64> <trusted-didx509> <policy.hex> <uvm-feed> <minimum-svn>\n",
            argv[0]);
        return 1;
    }

    Buffer report_hex = read_file(argv[1]);
    Buffer host_amd_cert_base64 = read_file(argv[2]);
    Buffer uvm_base64 = read_file(argv[3]);
    Buffer policy_hex = read_file(argv[5]);
    Buffer report = decode_hex(report_hex.data, report_hex.len, "report.hex");
    Buffer host_amd_json_bytes =
        decode_base64(host_amd_cert_base64.data, host_amd_cert_base64.len, "host-amd-cert.base64");
    Buffer uvm = decode_base64(uvm_base64.data, uvm_base64.len, "uvm.base64");
    Buffer policy = decode_hex(policy_hex.data, policy_hex.len, "policy.hex");
    OwnedString host_amd_json = buffer_to_c_string(host_amd_json_bytes, "host AMD certificate JSON");
    OwnedString vcek = json_string_value(host_amd_json.data, "vcekCert");
    OwnedString chain = json_string_value(host_amd_json.data, "certificateChain");
    OwnedString ask = {0};
    OwnedString ark = {0};
    split_pem_chain(chain.data, &ask, &ark);

    if (policy.len == 0 || policy.len % SNP_HOST_DATA_LEN != 0) {
        fprintf(
            stderr,
            "policy.hex must contain one or more %u-byte policy digests\n",
            (unsigned int)SNP_HOST_DATA_LEN);
        return 1;
    }
    size_t policy_count = policy.len / SNP_HOST_DATA_LEN;
    uint64_t minimum_svn = parse_u64(argv[7], "minimum-svn");
    const uint32_t minimum_tcb_cpuids[] = {0x00A00F11};
    const uint8_t minimum_tcb_values[] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xdb};
    const size_t minimum_tcb_count = 1;

    int exit_code = 0;
    TavSnpAttestationReport *attestation = NULL;
    TavCborValue *uvm_endorsement = NULL;
    TavByteBuffer *report_data = NULL;

    exit_code = consume_snp_error(
        tav_verify_snp_attestation(
            report.data,
            report.len,
            (const uint8_t *)ark.data,
            ark.len,
            (const uint8_t *)ask.data,
            ask.len,
            (const uint8_t *)vcek.data,
            vcek.len,
            &attestation),
        "verify attestation");
    if (exit_code != 0) {
        goto cleanup;
    }

    exit_code = consume_caci_error(
        tav_verify_caci_uvm_endorsement(
            uvm.data,
            uvm.len,
            argv[4],
            strlen(argv[4]),
            &uvm_endorsement),
        "verify UVM endorsement");
    if (exit_code != 0) {
        goto cleanup;
    }

    exit_code = consume_caci_error(
        tav_verify_caci_attestation(
            attestation,
            minimum_tcb_cpuids,
            minimum_tcb_values,
            minimum_tcb_count,
            policy.data,
            policy_count,
            uvm_endorsement,
            argv[6],
            strlen(argv[6]),
            minimum_svn,
            &report_data),
        "verify CACI attestation");
    if (exit_code != 0) {
        goto cleanup;
    }

    printf("Confidential CACI attestation verified.\n");
    printf("verified_report_data\n");
    print_hex_lines(tav_byte_buffer_data(report_data), tav_byte_buffer_len(report_data), 2);
    printf("verified_snp_attestation\n");
    print_borrowed_report_field("host_data", tav_snp_attestation_report_host_data, attestation);
    print_borrowed_report_field("report_data", tav_snp_attestation_report_report_data, attestation);
    print_borrowed_report_field("measurement", tav_snp_attestation_report_measurement, attestation);
    print_borrowed_report_field("reported_tcb", tav_snp_attestation_report_reported_tcb, attestation);
    printf("verified_uvm_endorsement\n");
    print_uvm_endorsement(uvm_endorsement);
    printf("policy_digest_count\n");
    printf("  %zu\n", policy_count);
    print_minimum_tcb(minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count);
    printf("uvm_feed\n");
    printf("  %s\n", argv[6]);
    printf("minimum_svn\n");
    printf("  %" PRIu64 "\n", minimum_svn);

cleanup:
    tav_byte_buffer_free(report_data);
    tav_cbor_value_free(uvm_endorsement);
    tav_snp_attestation_report_free(attestation);
    free_string(&ark);
    free_string(&ask);
    free_string(&chain);
    free_string(&vcek);
    free_string(&host_amd_json);
    free_buffer(&policy);
    free_buffer(&uvm);
    free_buffer(&host_amd_json_bytes);
    free_buffer(&report);
    free_buffer(&policy_hex);
    free_buffer(&uvm_base64);
    free_buffer(&host_amd_cert_base64);
    free_buffer(&report_hex);
    return exit_code;
}
