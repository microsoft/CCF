// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

using RawPolicy = std::string;
using DigestedPolicy = std::array<uint8_t, 32>;

namespace ccf
{
  using SecurityPolicies = ServiceMap<RawPolicy, DigestedPolicy>;
  namespace Tables
  {
    static constexpr auto SECURITY_POLICIES =
      "public:ccf.gov.security_policies";
  }
}