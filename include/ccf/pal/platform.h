// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf::pal
{
  enum class Platform
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

  constexpr static auto platform =
#if defined(PLATFORM_SGX)
    Platform::SGX
#elif defined(PLATFORM_SNP)
    Platform::SNP
#elif defined(PLATFORM_VIRTUAL)
    Platform::Virtual
#else
    Platform::Unknown
#endif
    ;
}