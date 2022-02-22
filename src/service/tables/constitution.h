// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service/map.h"

namespace ccf
{
  using Constitution = ServiceValue<std::string>;
  namespace Tables
  {
    static constexpr auto CONSTITUTION = "public:ccf.gov.constitution";
  }
}