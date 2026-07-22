// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Shared C ABI error codes.
 *
 * These values are mirrored by the Rust `TavErrorCode` enum in `ffi/src/lib.rs`.
 * Keep all public C ABI error accessors returning this single type.
 */
typedef enum TavErrorCode {
    /* Common codes, returned from any domain. */
    TAV_ERROR_OK = 0,
    TAV_ERROR_INVALID_ARGUMENT = 1,
    TAV_ERROR_IS_NULL = 2,
    TAV_ERROR_PANIC = 3,

    TAV_ERROR_SNP_UNSUPPORTED_PROCESSOR = 101,
    TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE = 102,
    TAV_ERROR_SNP_CERTIFICATE_CHAIN_ERROR = 103,
    TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR = 104,
    TAV_ERROR_SNP_TCB_VERIFICATION_ERROR = 105,

    TAV_ERROR_COSE_CBOR = 201,
    TAV_ERROR_COSE_UNEXPECTED_TYPE = 202,
    TAV_ERROR_COSE_UNSUPPORTED_ALGORITHM = 203,
    TAV_ERROR_COSE_KEY_IMPORT = 204,
    TAV_ERROR_COSE_VERIFICATION = 205,

    TAV_ERROR_CACI_COSE = 301,
    TAV_ERROR_CACI_CERTIFICATE = 302,
    TAV_ERROR_CACI_DID_X509 = 303,
    TAV_ERROR_CACI_SIGNATURE = 304,
    TAV_ERROR_CACI_MEASUREMENT = 305,
    TAV_ERROR_CACI_POLICY = 306,
} TavErrorCode;

typedef struct TavError TavError;

TavErrorCode tav_error_code(const TavError *error);
const char *tav_error_message(const TavError *error);
void tav_error_free(TavError *error);

/*
 * Opaque owned byte buffer returned by public C ABI functions.
 *
 * Producing functions write an owned TavByteBuffer* through an out-parameter.
 * Read its contents with tav_byte_buffer_data and tav_byte_buffer_len, then
 * release it with tav_byte_buffer_free. The type is intentionally opaque so a
 * caller cannot construct one over foreign memory: every buffer passed to
 * tav_byte_buffer_free is one this library allocated.
 *
 * tav_byte_buffer_data returns a pointer valid until the buffer is freed; it is
 * non-NULL even for a zero-length buffer, so always pair it with
 * tav_byte_buffer_len. Passing NULL to an accessor or to tav_byte_buffer_free is
 * a no-op (data returns NULL, len returns 0).
 */
typedef struct TavByteBuffer TavByteBuffer;

const uint8_t *tav_byte_buffer_data(const TavByteBuffer *bytes);
size_t tav_byte_buffer_len(const TavByteBuffer *bytes);
void tav_byte_buffer_free(TavByteBuffer *bytes);

#ifdef __cplusplus
}
#endif
