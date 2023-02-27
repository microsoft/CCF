// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"
#include "ccf/pal/measurement.h"

namespace ccf
{
  // Generic wrapper for code digests on all TEE platforms
  struct CodeDigest // TODO: Rename?
  {
    // TODO: Enforce size invariants for SGX and SNP
    // TODO: Should this be a vector instead??
    // pal::AttestationMeasurement data;
    std::vector<uint8_t> data;
    // std::array<uint8_t, 64> data;

    CodeDigest() = default;
    CodeDigest(const CodeDigest&) = default;

    template <size_t N>
    CodeDigest(const pal::AttestationMeasurement<N>& measurement) :
      data(measurement.data.begin(), measurement.data.end())
    {}

    CodeDigest& operator=(const CodeDigest&) = default;

    std::string hex_str() const
    {
      return ds::to_hex(data);
    }
  };
  DECLARE_JSON_TYPE(CodeDigest);
  DECLARE_JSON_REQUIRED_FIELDS(CodeDigest, data);

  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "AllowedToJoin"}});
}