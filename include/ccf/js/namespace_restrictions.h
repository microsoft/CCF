// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/map_access_permissions.h"

#include <regex>
#include <vector>

namespace ccf::js
{
  struct NamespaceRestriction
  {
    std::regex regex;
    MapAccessPermissions permission;
  };

  using NamespaceRestrictions = std::vector<NamespaceRestriction>;
}