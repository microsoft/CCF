// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>

namespace ccf::env
{
  std::string expand_envvar(const std::string& str);

  std::string expand_envvars_in_path(const std::string& str);
}
