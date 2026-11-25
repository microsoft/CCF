// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

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

    TAV_ERROR_CBOR_DECODE_FAILED = 401,
    TAV_ERROR_CBOR_KEY_NOT_FOUND = 402,
    TAV_ERROR_CBOR_OUT_OF_BOUND = 403,
    TAV_ERROR_CBOR_TYPE_MISMATCH = 404,
    TAV_ERROR_CBOR_ENCODE_FAILED = 405,
} TavErrorCode;

typedef struct TavError TavError;

TavErrorCode tav_error_code(const TavError *error);
const char *tav_error_message(const TavError *error);
void tav_error_free(TavError *error);

#ifdef __cplusplus
}
#endif
