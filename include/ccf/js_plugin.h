// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <string>

namespace ccf::js
{
  namespace core
  {
    class Context;
  }

  struct FFIPlugin
  {
    std::string name;
    std::string ccf_version;
    std::function<void(core::Context& ctx)> extend;
  };
}
