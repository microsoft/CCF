// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"

#include <functional>
#include <string>

namespace ccf::js
{
  enum class MapAccessPermissions
  {
    READ_WRITE,
    READ_ONLY,
    ILLEGAL
  };

  using PermissionDeniedDescriber = std::function<std::string(
    js::core::Context& ctx,
    const std::string& function,
    const std::string& map_name,
    MapAccessPermissions access_permission)>;
}
