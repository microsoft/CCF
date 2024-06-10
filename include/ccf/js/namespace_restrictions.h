// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/kv_access_permissions.h"

#include <functional>
#include <string>

namespace ccf::js
{
  // A function which calculates some access permission based on the given map
  // name. Should also populate an explanation, which can be included in error
  // messages if disallowed methods are accessed.
  using NamespaceRestriction = std::function<KVAccessPermissions(
    const std::string& map_name, std::string& explanation)>;
}