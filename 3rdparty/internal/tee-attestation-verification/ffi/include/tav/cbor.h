// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <tav/byte_buffer.h>
#include <tav/errors.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for building, serializing, parsing and inspecting CBOR documents.
 *
 * Fallible calls return NULL on success or an owned TavError* on failure.
 * Read errors with tav_error_code and tav_error_message, then release them
 * with tav_error_free. Panics are reported as TAV_ERROR_PANIC.
 *
 * Handles:
 * - Every handle is independently owned and keeps its complete immutable CBOR
 *   document alive. Every handle is released with tav_cbor_free;
 *   tav_cbor_free(NULL) is a no-op.
 * - Container constructors consume every handle passed to them and set each
 *   caller variable to NULL. A batch containing NULL or the same handle more
 *   than once is rejected without consuming any handles.
 *   A null output slot is rejected before consuming inputs.
 * - Navigation returns a new owning handle projected into the same immutable
 *   document. It remains valid after the source handle is freed.
 * - CBOR, COSE, and CACI use TavCborHandle directly. Free each owned handle
 *   exactly once.
 *
 * Payloads:
 * - Scalars are copied. tav_cbor_make_bytes and tav_cbor_make_string borrow:
 *   the caller's memory must remain alive and unmodified while any handle
 *   derived from it is in use. Parsing has the same borrowing contract.
 *   Accessor views must not outlive their payload storage. Owned payload
 *   views must not outlive the handle used to obtain them.
 * - tav_cbor_deep_copy copies every payload, so its result depends on no
 *   caller buffer.
 * - Serialization output is newly allocated and owned by the caller.
 *
 * Out-parameters:
 * - Owned handle and serialization outputs are cleared to NULL before work.
 *   Release a previous result before reusing its slot. Output slots must not
 *   alias input slots or any memory read by the call.
 * - Every other output is written only on success, so a failed call leaves
 *   its previous value alone. The returned error says whether it was written.
 * - A call whose required out-parameter is NULL returns an error.
 *
 * Errors:
 * - Constructors and copies use TAV_ERROR_CBOR_ENCODE_FAILED for invalid
 *   inputs, including reserved simple values, invalid UTF-8, and bad batches.
 * - Parsing uses TAV_ERROR_CBOR_DECODE_FAILED for invalid input.
 * - Reads and navigation use TAV_ERROR_CBOR_TYPE_MISMATCH for null arguments
 *   or an unexpected kind. Missing keys/tags and bad indices have distinct
 *   TAV_ERROR_CBOR_KEY_NOT_FOUND and TAV_ERROR_CBOR_OUT_OF_BOUND codes.
 * - Constructors, copies, parsing, and serialization use
 *   TAV_ERROR_INVALID_ARGUMENT for a null output slot.
 * - Input buffers and handle batches must fit in PTRDIFF_MAX bytes.
 */

typedef struct TavCborHandle TavCborHandle;

/*
 * Limits. Parsing and serialization take a nesting depth, max_depth.
 * Non-deterministic parsing also limits the key/value pairs in any one map,
 * at any level, and rejects maps inside map keys.
 *
 * - Depth: TAV_CBOR_DEFAULT_MAX_DEPTH is the default, recommended for
 *   untrusted input, the limit the C++ wrapper applies unless told otherwise
 *   and the one COSE and CACI verification parse within. TAV_CBOR_MAX_DEPTH
 *   is the hard cap, which a larger request is clamped to.
 * - Map entries: non-deterministic parsing applies TAV_CBOR_MAX_MAP_ENTRIES,
 *   as COSE and CACI verification do. Deterministic parsing and
 *   serialization apply neither the entry limit nor the map key rule.
 *
 * Builders do not enforce these limits. Callers must bound the depth they
 * build. Copying, materializing, or dropping an extremely deep value can
 * exhaust the process stack and abort.
 *
 * For untrusted input, keep the default depth, and bound the length of the
 * input before parsing it, since no parser does. A larger depth makes
 * parsing more expensive:
 *
 * - Parsing can cost time proportional to max_depth times the input length,
 *   because building a value skips over each item once for every array or map
 *   it is nested in. Expect a document nested to the hard cap to take up to
 *   four times as long as one nested to the default.
 * - Every non-deterministic parse allocates and zeroes
 *   3 * (max_depth + 1) * TAV_CBOR_MAX_MAP_ENTRIES size_t words of scratch,
 *   whatever the input length. On a 64-bit target that is about 52 KB at the
 *   default depth and about 0.2 MB at the hard cap.
 *
 * A parsed document takes about 40 bytes for every item on a 64-bit target,
 * so input made of one-byte items takes about 40 times its length in memory.
 *
 * COSE and CACI verification leave input sizes unchecked too.
 */
#define TAV_CBOR_DEFAULT_MAX_DEPTH 16
#define TAV_CBOR_MAX_DEPTH 64
#define TAV_CBOR_MAX_MAP_ENTRIES 128

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

/* Scalar constructors, which copy. Reserved simple values are rejected. */
TavError* tav_cbor_make_signed(int64_t value, TavCborHandle** out);
TavError* tav_cbor_make_simple(uint8_t value, TavCborHandle** out);

/* Payload constructors, which borrow data for the life of the handle. */
TavError* tav_cbor_make_bytes(const uint8_t* data, size_t len, TavCborHandle** out);
/* data must be valid UTF-8. */
TavError* tav_cbor_make_string(const char* data, size_t len, TavCborHandle** out);

/* Container constructors, which consume every handle passed to them. */
TavError* tav_cbor_make_array(TavCborHandle** items, size_t count, TavCborHandle** out);
/*
 * pairs holds key, value, key, value, ... so it has 2 * pair_count entries.
 * Keys may be any supported CBOR value and must be unique. Duplicate
 * keys are unsupported: construction may succeed, but serialization fails.
 */
TavError* tav_cbor_make_map(TavCborHandle** pairs, size_t pair_count, TavCborHandle** out);
TavError* tav_cbor_make_tagged(uint64_t tag, TavCborHandle** payload, TavCborHandle** out);

/*
 * Copy a value and everything below it. Each payload keeps the ownership the
 * source had: borrowed payloads are borrowed again from the same buffer, and
 * owned payloads are copied. Writes an owned handle on success.
 */
TavError* tav_cbor_shallow_copy(const TavCborHandle* value, TavCborHandle** out);

/*
 * Copy a value and everything below it, copying every payload, so the result
 * borrows nothing. Writes an owned handle on success.
 */
TavError* tav_cbor_deep_copy(const TavCborHandle* value, TavCborHandle** out);

void tav_cbor_free(TavCborHandle* value);

/*
 * Serialization writes an owned buffer through out on success.
 * Read it with tav_byte_buffer_data/tav_byte_buffer_len and release it with
 * tav_byte_buffer_free. Failures use TAV_ERROR_CBOR_ENCODE_FAILED.
 */
TavError* tav_cbor_nondet_serialize(
  const TavCborHandle* value, size_t max_depth, TavByteBuffer** out);

/* Deterministic encoding. */
TavError* tav_cbor_det_serialize(
  const TavCborHandle* value, size_t max_depth, TavByteBuffer** out);

/*
 * Parsing. On success writes an owning handle through out_value. The returned
 * tree borrows byte and text payloads from data, which must outlive it.
 * Bound the length of untrusted data first, and keep the default depth for
 * it, as described with the limits above.
 *
 * Map keys use RFC 8949 equivalence, including order-independent map
 * comparison for keys parsed deterministically.
 */
TavError* tav_cbor_nondet_parse(
  const uint8_t* data,
  size_t len,
  size_t max_depth,
  TavCborHandle** out_value);

/* Requires deterministic encoding. */
TavError* tav_cbor_det_parse(
  const uint8_t* data,
  size_t len,
  size_t max_depth,
  TavCborHandle** out_value);

/* Inspection. Returns TAV_CBOR_HANDLE_KIND_INVALID for NULL, otherwise the kind.
 */
int tav_cbor_kind(const TavCborHandle* value);
TavError* tav_cbor_as_signed(const TavCborHandle* value, int64_t* out);
TavError* tav_cbor_as_simple(const TavCborHandle* value, uint8_t* out);
TavError* tav_cbor_as_bytes(const TavCborHandle* value, const uint8_t** out, size_t* out_len);
TavError* tav_cbor_as_string(const TavCborHandle* value, const char** out, size_t* out_len);
/* The tag of a tagged value. Pair with tav_cbor_tag_at to reach the payload. */
TavError* tav_cbor_as_tag(const TavCborHandle* value, uint64_t* out);

/* Array or map entry count. TAV_ERROR_CBOR_TYPE_MISMATCH for anything else. */
TavError* tav_cbor_size(const TavCborHandle* value, size_t* out);

/*
 * Navigation. Each writes a new owning handle through out. The output is
 * cleared before any work, and must be released with tav_cbor_free or passed
 * to a consuming container constructor. out must point to a null handle slot
 * separate from every input-handle variable.
 *
 * Errors use TAV_ERROR_CBOR_* codes:
 * array_at: TYPE_MISMATCH if not an array, OUT_OF_BOUND past the end.
 * map_at:   TYPE_MISMATCH if not a map, KEY_NOT_FOUND if absent.
 * tag_at:   TYPE_MISMATCH if not tagged, KEY_NOT_FOUND if the tag differs.
 */
TavError* tav_cbor_array_at(const TavCborHandle* value, size_t index, TavCborHandle** out);
TavError* tav_cbor_map_at(const TavCborHandle* value, const TavCborHandle* key, TavCborHandle** out);
TavError* tav_cbor_tag_at(const TavCborHandle* value, uint64_t tag, TavCborHandle** out);

/* Map enumeration, for callers that walk rather than look up. */
TavError* tav_cbor_map_key_at(const TavCborHandle* value, size_t index, TavCborHandle** out);
TavError* tav_cbor_map_value_at(const TavCborHandle* value, size_t index, TavCborHandle** out);

#ifdef __cplusplus
}
#endif
