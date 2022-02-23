// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/service/map.h"
#include "resharing_types.h"

namespace ccf
{
  using Resharings = ServiceMap<kv::ReconfigurationId, ResharingResult>;
  namespace Tables
  {
    static constexpr auto RESHARINGS = "public:ccf.internal.resharings";
  }
}