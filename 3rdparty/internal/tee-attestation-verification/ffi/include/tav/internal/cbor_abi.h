// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for building, serializing, parsing and inspecting CBOR documents.
 *
 * Internal to <tav/cbor.hpp>, which owns the ownership and lifetime
 * contract. Not a supported interface on its own.
 *
 * Handles:
 * - Every handle is independently owned and keeps its complete immutable CBOR
 *   document alive. Every handle is released with tav_cbor_free;
 *   tav_cbor_free(NULL) is a no-op.
 * - Container constructors consume every handle passed to them and set each
 *   caller variable to NULL. A batch containing NULL or the same handle more
 *   than once is rejected without consuming any handles. A map with an invalid
 *   key is also rejected without consuming any handles.
 * - Navigation returns a new owning handle projected into the same immutable
 *   document. It remains valid after the source handle is freed.
 *
 * Payloads:
 * - Scalars are copied. tav_cbor_make_bytes and tav_cbor_make_string borrow:
 *   the handle stores the caller's pointer and length, and so does every
 *   pointer returned by tav_cbor_as_bytes and tav_cbor_as_string.
 * - tav_cbor_deep_copy copies every payload, so its result depends on no
 *   caller buffer.
 * - Serialization output is newly allocated and owned by the caller.
 *
 * Out-parameters:
 * - Outputs the caller must release, meaning the parse handle, the
 *   serialization buffer and the error message, are cleared to NULL or zero
 *   before any work. A failed call therefore leaves no earlier pointer in
 *   place, and a slot reused across calls is never freed twice.
 * - Every other output is written only on success, so a failed call leaves
 *   its previous value alone. The status says whether it was written.
 * - A call whose out-parameter is NULL reports a status rather than writing.
 *   err_ptr and err_len may be NULL, which suppresses the message.
 */

typedef struct TavCborHandle TavCborHandle;

/*
 * Ceiling on nesting depth for parsing and serialization. Builders do not
 * enforce this limit. Callers must bound the depth they build. Copying,
 * materializing, or dropping an extremely deep value can exhaust the process
 * stack and abort.
 */
#define TAV_CBOR_MAX_DEPTH 256

/*
 * Status codes, named for use with the int returned by the calls below. The
 * enum type itself is not used in any signature, because a C enum has
 * implementation-defined width.
 */
typedef enum TavCborStatus
{
    TAV_CBOR_OK = 0,
    TAV_CBOR_DECODE_FAILED = 1,
    TAV_CBOR_KEY_NOT_FOUND = 2,
    TAV_CBOR_OUT_OF_BOUND = 3,
    TAV_CBOR_TYPE_MISMATCH = 4,
    TAV_CBOR_ENCODE_FAILED = 5,
} TavCborStatus;

/*
 * Value kinds, named for use with tav_cbor_kind. The enum type itself is not
 * used in any signature, because a C enum has implementation-defined width.
 */
typedef enum TavCborHandleKind
{
    TAV_CBOR_HANDLE_KIND_INVALID = -1,
    TAV_CBOR_HANDLE_KIND_SIGNED = 0,
    TAV_CBOR_HANDLE_KIND_BYTES = 1,
    TAV_CBOR_HANDLE_KIND_STRING = 2,
    TAV_CBOR_HANDLE_KIND_ARRAY = 3,
    TAV_CBOR_HANDLE_KIND_MAP = 4,
    TAV_CBOR_HANDLE_KIND_TAGGED = 5,
    TAV_CBOR_HANDLE_KIND_SIMPLE = 6,
} TavCborHandleKind;

/* Scalar constructors, which copy. Return NULL on failure. */
TavCborHandle* tav_cbor_make_signed(int64_t value);
TavCborHandle* tav_cbor_make_simple(uint8_t value);

/* Payload constructors, which borrow data for the life of the handle. */
TavCborHandle* tav_cbor_make_bytes(const uint8_t* data, size_t len);
/* data must be valid UTF-8. */
TavCborHandle* tav_cbor_make_string(const char* data, size_t len);

/* Container constructors, which consume every handle passed to them. */
TavCborHandle* tav_cbor_make_array(TavCborHandle** items, size_t count);
/*
 * pairs holds key, value, key, value, ... so it has 2 * pair_count entries.
 * Keys must be unique and must not be arrays, maps or tagged values. Duplicate
 * keys are unsupported: construction may succeed, but serialization fails.
 */
TavCborHandle* tav_cbor_make_map(TavCborHandle** pairs, size_t pair_count);
TavCborHandle* tav_cbor_make_tagged(uint64_t tag, TavCborHandle** payload);

/*
 * Copy a value and everything below it. Each payload keeps the ownership the
 * source had: borrowed payloads are borrowed again from the same buffer, and
 * owned payloads are copied. Returns NULL on failure.
 */
TavCborHandle* tav_cbor_shallow_copy(const TavCborHandle* value);

/*
 * Copy a value and everything below it, copying every payload, so the result
 * borrows nothing. Returns NULL on failure.
 */
TavCborHandle* tav_cbor_deep_copy(const TavCborHandle* value);

void tav_cbor_free(TavCborHandle* value);

/*
 * Serialization. On success writes an owned buffer through out_ptr/out_len,
 * released with tav_cbor_buffer_free. On failure writes a UTF-8 message, not
 * NUL terminated, through err_ptr/err_len, released the same way; passing
 * NULL for both suppresses the message.
 */
int tav_cbor_nondet_serialize(
  const TavCborHandle* value,
  size_t max_depth,
  uint8_t** out_ptr,
  size_t* out_len,
  uint8_t** err_ptr,
  size_t* err_len);

/* Deterministic encoding. */
int tav_cbor_det_serialize(
  const TavCborHandle* value,
  size_t max_depth,
  uint8_t** out_ptr,
  size_t* out_len,
  uint8_t** err_ptr,
  size_t* err_len);

/*
 * Parsing. On success writes an owning handle through out_value. The returned
 * tree borrows byte and text payloads from data, which must outlive it.
 *
 * A document whose maps key an entry on an array, map or tagged value is
 * rejected, so a parsed map holds only keys map_at can look up.
 */
int tav_cbor_nondet_parse(
  const uint8_t* data,
  size_t len,
  size_t max_depth,
  TavCborHandle** out_value,
  uint8_t** err_ptr,
  size_t* err_len);

/* Requires deterministic encoding. */
int tav_cbor_det_parse(
  const uint8_t* data,
  size_t len,
  size_t max_depth,
  TavCborHandle** out_value,
  uint8_t** err_ptr,
  size_t* err_len);

void tav_cbor_buffer_free(uint8_t* ptr, size_t len);

/* Inspection. Returns one of the TAV_CBOR_HANDLE_KIND_* values. */
int tav_cbor_kind(const TavCborHandle* value);
int tav_cbor_as_signed(const TavCborHandle* value, int64_t* out);
int tav_cbor_as_simple(const TavCborHandle* value, uint8_t* out);
int tav_cbor_as_bytes(const TavCborHandle* value, const uint8_t** out, size_t* out_len);
int tav_cbor_as_string(const TavCborHandle* value, const char** out, size_t* out_len);
/* The tag of a tagged value. Pair with tav_cbor_tag_at to reach the payload. */
int tav_cbor_as_tag(const TavCborHandle* value, uint64_t* out);

/* Array or map entry count. TAV_CBOR_TYPE_MISMATCH for anything else. */
int tav_cbor_size(const TavCborHandle* value, size_t* out);

/*
 * Navigation. Each writes a new owning handle through out. The output is
 * cleared before any work, and must be released with tav_cbor_free or passed
 * to a consuming container constructor. out must point to a null handle slot
 * separate from every input-handle variable.
 *
 * array_at: TYPE_MISMATCH if not an array, OUT_OF_BOUND past the end.
 * map_at:   TYPE_MISMATCH if not a map or if the key is a container, which a
 *           map cannot hold,
 *           KEY_NOT_FOUND if absent.
 * tag_at:   TYPE_MISMATCH if not tagged, KEY_NOT_FOUND if the tag differs.
 */
int tav_cbor_array_at(const TavCborHandle* value, size_t index, TavCborHandle** out);
int tav_cbor_map_at(const TavCborHandle* value, const TavCborHandle* key, TavCborHandle** out);
int tav_cbor_tag_at(const TavCborHandle* value, uint64_t tag, TavCborHandle** out);

/* Map enumeration, for callers that walk rather than look up. */
int tav_cbor_map_key_at(const TavCborHandle* value, size_t index, TavCborHandle** out);
int tav_cbor_map_value_at(const TavCborHandle* value, size_t index, TavCborHandle** out);

#ifdef __cplusplus
}
#endif
