// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tav/utils.h"

#define TAV_COSE_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for CBOR parsing/navigation and COSE_Sign1 verification.
 *
 * Ownership and lifetime:
 * - tav_cbor_value_from_bytes returns an owned TavCborValue. Release it with
 *   tav_cbor_value_free.
 * - CBOR child accessors, including array/map/tag accessors, return borrowed
 *   handles. Borrowed handles must not be freed and remain valid only while the
 *   ancestor owned TavCborValue remains alive.
 * - Byte/text accessors return borrowed views. The returned data remains valid
 *   only while the owning or ancestor TavCborValue remains alive.
 * - tav_cbor_value_to_bytes writes an owned TavByteBuffer* through out_bytes.
 *   Read it with tav_byte_buffer_data/tav_byte_buffer_len and release it with
 *   tav_byte_buffer_free.
 * - Freeing NULL owned handles is a no-op.
 * - Owned out-parameters are write-only: pass a non-NULL pointer to a handle
 *   slot. The slot is set to NULL before any fallible work and set to an owned
 *   handle only on success.
 * - Error accessors are defensive for NULL TavError pointers:
 *   tav_error_code returns TAV_ERROR_IS_NULL and tav_error_message returns
 *   a static diagnostic string.
 */

typedef enum TavCborKind {
    TAV_CBOR_KIND_INT = 1,
    TAV_CBOR_KIND_SIMPLE = 2,
    TAV_CBOR_KIND_BYTES = 3,
    TAV_CBOR_KIND_TEXT = 4,
    TAV_CBOR_KIND_ARRAY = 5,
    TAV_CBOR_KIND_MAP = 6,
    TAV_CBOR_KIND_TAGGED = 7,
} TavCborKind;

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

typedef struct TavCborValue TavCborValue;

TAV_COSE_API TavError *tav_cbor_value_from_bytes(
    const uint8_t *bytes,
    size_t len,
    TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_to_bytes(
    const TavCborValue *value,
    TavByteBuffer **out_bytes);

/* value must be a valid, non-NULL TavCborValue handle. */
TAV_COSE_API TavCborKind tav_cbor_value_kind(const TavCborValue *value);

TAV_COSE_API TavError *tav_cbor_value_int(
    const TavCborValue *value,
    int64_t *out);

TAV_COSE_API TavError *tav_cbor_value_simple(
    const TavCborValue *value,
    uint8_t *out);

TAV_COSE_API TavError *tav_cbor_value_bytes(
    const TavCborValue *value,
    const uint8_t **data,
    size_t *len);

TAV_COSE_API TavError *tav_cbor_value_text(
    const TavCborValue *value,
    const char **text,
    size_t *len);

TAV_COSE_API TavError *tav_cbor_value_tag(
    const TavCborValue *value,
    uint64_t *out);

TAV_COSE_API TavError *tav_cbor_value_tagged_payload(
    const TavCborValue *value,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_len(
    const TavCborValue *value,
    size_t *out);

TAV_COSE_API TavError *tav_cbor_value_array_at(
    const TavCborValue *value,
    size_t index,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_at_int(
    const TavCborValue *value,
    int64_t key,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_at_text(
    const TavCborValue *value,
    const char *key,
    size_t key_len,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_at(
    const TavCborValue *value,
    const TavCborValue *key,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_has_int_key(
    const TavCborValue *value,
    int64_t key,
    bool *out);

TAV_COSE_API TavError *tav_cbor_value_map_has_text_key(
    const TavCborValue *value,
    const char *key,
    size_t key_len,
    bool *out);

TAV_COSE_API TavError *tav_cbor_value_map_has_key(
    const TavCborValue *value,
    const TavCborValue *key,
    bool *out);

TAV_COSE_API TavError *tav_cbor_value_map_entry_at(
    const TavCborValue *value,
    size_t index,
    const TavCborValue **out_key,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_key_at(
    const TavCborValue *value,
    size_t index,
    const TavCborValue **out_key);

TAV_COSE_API TavError *tav_cbor_value_map_value_at(
    const TavCborValue *value,
    size_t index,
    const TavCborValue **out_value);

TAV_COSE_API TavError *tav_validate_cose_sign1(
    const TavCborValue *value,
    const TavCborValue **out_sign1);

TAV_COSE_API void tav_cbor_value_free(TavCborValue *value);


TAV_COSE_API TavError *tav_verify_cose_sign1_embedded(
    const TavCborValue *sign1,
    const uint8_t *spki_der,
    size_t spki_der_len,
    int32_t cose_alg);

TAV_COSE_API TavError *tav_verify_cose_sign1_detached(
    const TavCborValue *sign1,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *spki_der,
    size_t spki_der_len,
    int32_t cose_alg);

#ifdef __cplusplus
}
#endif
