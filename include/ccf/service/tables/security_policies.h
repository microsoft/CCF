// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

using DigestedPolicy = std::array<uint8_t, 32>;
using RawPolicy = std::string;

namespace ccf
{
  using SecurityPolicies = ServiceMap<DigestedPolicy, RawPolicy>;
  namespace Tables
  {
    static constexpr auto SECURITY_POLICIES =
      "public:ccf.gov.security_policies";
  }
}