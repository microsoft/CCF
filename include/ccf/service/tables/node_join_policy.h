// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/value.h"

namespace ccf
{
  using CodeUpdatePolicy = ccf::kv::RawCopySerialisedValue<std::string>;

  namespace Tables
  {
    static constexpr auto NODE_JOIN_POLICY =
      "public:ccf.gov.nodes.node_join_policy";
  }
}
