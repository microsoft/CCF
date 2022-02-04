// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service/map.h"

#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

namespace ccf
{
  using Module = std::string;
  using Modules = kv::RawCopySerialisedMap<std::string, Module>;
  using ModulesQuickJsBytecode =
    kv::RawCopySerialisedMap<std::string, std::vector<uint8_t>>;
  using ModulesQuickJsVersion = kv::RawCopySerialisedValue<std::string>;
}