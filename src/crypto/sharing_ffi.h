// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#  define CCF_SHAMIR_NODISCARD [[nodiscard]]
#elif defined(__GNUC__)
#  define CCF_SHAMIR_NODISCARD __attribute__((warn_unused_result))
#else
#  define CCF_SHAMIR_NODISCARD
#endif

#ifdef __cplusplus
extern "C"
{
#endif
  typedef struct
  {
    uint32_t x;
    uint32_t y[10];
  } ccf_shamir_share;

  typedef enum
  {
    CCF_SHAMIR_OK = 0,
    // Null, misaligned, empty, oversized or overlapping buffers, or lengths
    // outside the supported range.
    CCF_SHAMIR_INVALID_ARGUMENTS = 1,
    // A polynomial coefficient is not canonical, i.e. not below the prime.
    CCF_SHAMIR_INVALID_COEFFICIENT = 2,
    // Two input shares have the same x coordinate modulo the prime.
    CCF_SHAMIR_DUPLICATE_SHARE = 3,
    // The weights workspace does not have one entry per input share.
    CCF_SHAMIR_INVALID_WORKSPACE = 4,
  } ccf_shamir_status;

  // All buffers must be live, and are validated before use: null, misaligned,
  // empty, oversized, or mutually overlapping buffers are rejected. Lengths
  // are in elements. No concurrent access to output buffers is allowed.
  CCF_SHAMIR_NODISCARD uint64_t ccf_shamir_reduce(uint64_t x);
  CCF_SHAMIR_NODISCARD ccf_shamir_status ccf_shamir_evaluate(
    const uint64_t* coefficients,
    size_t coefficient_count,
    uint32_t* values,
    size_t share_count);
  // Only the first threshold shares are read. weights has threshold entries;
  // secret has ten entries, and is unchanged on error.
  CCF_SHAMIR_NODISCARD ccf_shamir_status ccf_shamir_recover(
    const ccf_shamir_share* shares,
    size_t threshold,
    uint64_t* weights,
    uint32_t* secret);
#ifdef __cplusplus
}
#endif
