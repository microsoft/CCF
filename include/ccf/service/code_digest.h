// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"
#include "ccf/pal/measurement.h"

namespace ccf
{
  // Generic wrapper for code digests on all TEE platforms
  // TODO: Rename and make private?
  struct PlatformAttestationMeasurement
  {
    std::vector<uint8_t> data;

    PlatformAttestationMeasurement() = default;
    PlatformAttestationMeasurement(const PlatformAttestationMeasurement&) = default;

    template <size_t N>
    PlatformAttestationMeasurement(const pal::AttestationMeasurement<N>& measurement) :
      data(measurement.measurement.begin(), measurement.measurement.end())
    {}

    PlatformAttestationMeasurement& operator=(const PlatformAttestationMeasurement&) = default;

    std::string hex_str() const
    {
      return ds::to_hex(data);
    }

    operator std::span<const uint8_t>() const
    {
      return data;
    }
  };
  DECLARE_JSON_TYPE(PlatformAttestationMeasurement);
  DECLARE_JSON_REQUIRED_FIELDS(PlatformAttestationMeasurement, data);

  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "AllowedToJoin"}});
}