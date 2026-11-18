// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
