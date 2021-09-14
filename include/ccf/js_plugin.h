// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <quickjs/quickjs.h>
#include <string>

namespace ccf
{
  namespace js
  {
    struct FFIPlugin
    {
      std::string name;
      std::string ccf_version;
      std::function<void(JSContext* ctx)> extend;
    };
  }
}