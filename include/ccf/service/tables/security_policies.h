// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"
#include "ccf/crypto/sha256_hash.h"

using DigestedPolicy = crypto::Sha256Hash;
using RawPolicy = std::string;

namespace ccf
{
  using SecurityPolicies = ServiceMap<DigestedPolicy, RawPolicy>;
  namespace Tables
  {
    static constexpr auto SECURITY_POLICIES =
      "public:ccf.gov.nodes.security_policies";
  }
}