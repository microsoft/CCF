// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

// Generated from src/rust/src/shamir.rs by scripts/generate-shamir-header.sh.
// Do not edit by hand.

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#  define CCF_SHAMIR_NODISCARD [[nodiscard]]
#elif defined(__GNUC__)
#  define CCF_SHAMIR_NODISCARD __attribute__((warn_unused_result))
#else
#  define CCF_SHAMIR_NODISCARD
#endif

// The number of 32-bit limbs in a secret and in each share.
#define CCF_SHAMIR_LIMBS 10

// Status codes returned by every fallible entry point of the C ABI.
typedef enum
{
  // Success.
  CCF_SHAMIR_STATUS_OK = 0,
  // Null, misaligned, empty, oversized or overlapping buffers, or lengths
  // outside the supported range.
  CCF_SHAMIR_STATUS_INVALID_ARGUMENTS = 1,
  // A polynomial coefficient is not canonical, i.e. not below the prime.
  CCF_SHAMIR_STATUS_INVALID_COEFFICIENT = 2,
  // Two input shares have the same x coordinate modulo the prime.
  CCF_SHAMIR_STATUS_DUPLICATE_SHARE = 3,
  // Internal workspace mismatch. Cannot occur through this interface, which
  // sizes its own workspace, but kept so every core error has a name.
  CCF_SHAMIR_STATUS_INVALID_WORKSPACE = 4,
  // The workspace for the recovery could not be allocated.
  CCF_SHAMIR_STATUS_OUT_OF_MEMORY = 5,
} ccf_shamir_status;

// A share of a secret: `y[k]` is the value at `x` of the polynomial for limb
// `k`.
typedef struct
{
  uint32_t x;
  uint32_t y[CCF_SHAMIR_LIMBS];
} ccf_shamir_share;

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

  // Reduce any 64-bit value to its canonical representative below the prime.
  CCF_SHAMIR_NODISCARD uint64_t ccf_shamir_reduce(uint64_t x);

  // Evaluate the polynomial at x = i + 1 for the share at index i, record that
  // coordinate in the share, and store the value in the given limb. Other limbs
  // are unchanged. Lengths are in elements. Requires limb < CCF_SHAMIR_LIMBS
  // and 0 < coefficient_count <= share_count < 2^31 - 1.
  //
  // # Safety
  //
  // Null, misaligned, empty, oversized, or overlapping buffers are rejected
  // without dereferencing anything. Otherwise the buffers must be live for
  // their indicated lengths, and no buffer may be accessed concurrently for the
  // duration of this call.
  CCF_SHAMIR_NODISCARD
  ccf_shamir_status ccf_shamir_share_limb(
    const uint64_t* coefficients,
    size_t coefficient_count,
    size_t limb,
    ccf_shamir_share* shares,
    size_t share_count);

  // Recover the secret from the first threshold shares. The secret is written
  // in place by the verified core, without an intermediate copy, and is
  // unchanged on error.
  //
  // # Safety
  //
  // Null, misaligned, empty, oversized, or overlapping buffers are rejected
  // without dereferencing anything. Otherwise `shares` must be live for
  // `threshold` elements and not mutated concurrently, and `secret` must be
  // live for exclusive access.
  CCF_SHAMIR_NODISCARD
  ccf_shamir_status ccf_shamir_recover(
    const ccf_shamir_share* shares,
    size_t threshold,
    uint32_t (*secret)[CCF_SHAMIR_LIMBS]);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
