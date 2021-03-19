// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service_map.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  using ServicePrincipals = ServiceMap<std::string, nlohmann::json>;
}