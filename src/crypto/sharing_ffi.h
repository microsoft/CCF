// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
  typedef struct
  {
    uint32_t x;
    uint32_t y[10];
  } ccf_shamir_share;

  // All buffers must be live, and are validated before use: null, misaligned,
  // empty, oversized, or mutually overlapping buffers are rejected. Lengths
  // are in elements. No concurrent access to output buffers is allowed.
  // Return 0 on success, 1 for invalid buffers or lengths, 2 for noncanonical
  // coefficients, 3 for duplicate coordinates modulo the field prime, 4 for
  // invalid workspace.
  uint64_t ccf_shamir_reduce(uint64_t x);
  int32_t ccf_shamir_evaluate(
    const uint64_t* coefficients,
    size_t coefficient_count,
    uint32_t* values,
    size_t share_count);
  // Only the first threshold shares are read. weights has threshold entries;
  // secret has ten entries, and is unchanged on error.
  int32_t ccf_shamir_recover(
    const ccf_shamir_share* shares,
    size_t threshold,
    uint64_t* weights,
    uint32_t* secret);
#ifdef __cplusplus
}
#endif
