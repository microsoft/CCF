// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

namespace ccf
{
  using JSEngine = ServiceMap<std::string, size_t>;

  namespace Tables
  {
    static constexpr auto JSENGINE = "public:ccf.gov.jsengine";
  }
}