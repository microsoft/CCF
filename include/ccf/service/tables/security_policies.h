// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

namespace ccf
{
  using SecurityPolicies = ServiceSet<std::string>;
  namespace Tables
  {
    static constexpr auto SECURITY_POLICIES =
      "public:ccf.gov.security_policies";
  }
}