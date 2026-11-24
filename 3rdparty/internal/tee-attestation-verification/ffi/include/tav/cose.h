// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tav/cbor.h>

#define TAV_COSE_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * COSE_Sign1 validation and verification over TavCborHandle values.
 * Parse, inspect, and serialize CBOR with tav/cbor.h.
 *
 * Fallible calls return NULL on success or an owned TavError* on failure.
 * Release errors with tav_error_free.
 *
 * Validation returns an independently owned handle sharing its input's
 * immutable document. Free it with tav_cbor_free. It remains valid after the
 * parent handle is freed, but borrowed input must remain alive and unchanged
 * until every derived handle is freed.
 *
 * out_sign1 is reset to NULL before any fallible work. Verification borrows
 * its inputs for the duration of the call and does not consume handles.
 */

/*
 * Input sizes are unchecked: bound untrusted input before parsing or verifying
 * it.
 */

typedef enum TavCoseAlgorithm {
    TAV_COSE_ALG_ES256 = -7,
    TAV_COSE_ALG_ES384 = -35,
    TAV_COSE_ALG_ES512 = -36,
    TAV_COSE_ALG_PS256 = -37,
    TAV_COSE_ALG_PS384 = -38,
    TAV_COSE_ALG_PS512 = -39,
} TavCoseAlgorithm;

typedef enum TavCoseTag {
    TAV_COSE_TAG_SIGN1 = 18,
} TavCoseTag;

typedef enum TavCoseSign1Field {
    TAV_COSE_SIGN1_PROTECTED = 0,
    TAV_COSE_SIGN1_UNPROTECTED = 1,
    TAV_COSE_SIGN1_PAYLOAD = 2,
    TAV_COSE_SIGN1_SIGNATURE = 3,
} TavCoseSign1Field;

typedef enum TavCoseHeaderLabel {
    TAV_COSE_HEADER_ALG = 1,
    TAV_COSE_HEADER_CWT_CLAIMS = 15,
    TAV_COSE_HEADER_X5CHAIN = 33,
    TAV_COSE_HEADER_CONTENT_TYPE = 3,
    TAV_COSE_HEADER_PREIMAGE_CONTENT_TYPE = 259,
} TavCoseHeaderLabel;

typedef enum TavCwtClaim {
    TAV_CWT_CLAIMS_ISSUER = 1,
    TAV_CWT_CLAIMS_SUBJECT = 2,
    TAV_CWT_CLAIMS_IAT = 6,
} TavCwtClaim;

TAV_COSE_API TavError *tav_validate_cose_sign1(
    const TavCborHandle *value,
    TavCborHandle **out_sign1);

TAV_COSE_API TavError *tav_verify_cose_sign1_embedded(
    const TavCborHandle *sign1,
    const uint8_t *spki_der,
    size_t spki_der_len,
    int32_t cose_alg);

TAV_COSE_API TavError *tav_verify_cose_sign1_detached(
    const TavCborHandle *sign1,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *spki_der,
    size_t spki_der_len,
    int32_t cose_alg);

#ifdef __cplusplus
}
#endif
