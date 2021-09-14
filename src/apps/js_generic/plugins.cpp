// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/js_openenclave_plugin.h"

namespace ccfapp
{

  std::vector<js::FFIPlugin> get_js_plugins()
  {
    return {js::openenclave_plugin};
  }

} // namespace ccfapp
