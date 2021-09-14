// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <vector>
#include "ccf/app_interface.h"
#include "ccf/js_plugin.h"

namespace ccfapp
{
  std::vector<ccf::js::FFIPlugin> __attribute__((weak)) get_js_plugins()
  {
    return {};
  }
}
