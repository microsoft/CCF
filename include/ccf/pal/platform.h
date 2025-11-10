// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/pal/snp_ioctl.h"

namespace ccf::pal
{
  enum class Platform : uint8_t
  {
    SGX = 0,
    SNP = 1,
    Virtual = 2,
    Unknown = 3,
  };
  DECLARE_JSON_ENUM(
    Platform,
    {{Platform::SGX, "SGX"},
     {Platform::SNP, "SNP"},
     {Platform::Virtual, "Virtual"},
     {Platform::Unknown, "Unknown"}});

  static Platform _detect_platform()
  {
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    auto* env_var = std::getenv("CCF_PLATFORM_OVERRIDE");
    if (env_var != nullptr)
    {
      return nlohmann::json(env_var).get<Platform>();
    }

    if (ccf::pal::snp::supports_sev_snp())
    {
      return Platform::SNP;
    }

    return Platform::Virtual;
  }

  // Default inits to Unknown.
  // Set this early from CLI, or explicitly for unit tests.
  static auto platform = _detect_platform();
}