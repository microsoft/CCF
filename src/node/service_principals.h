// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  using ServicePrincipals = kv::Map<std::string, nlohmann::json>;
}