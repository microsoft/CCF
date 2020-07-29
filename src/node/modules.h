// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "script.h"

namespace ccf
{
  using ModuleName = std::string;
  using Modules = kv::Map<ModuleName, Script>;
}