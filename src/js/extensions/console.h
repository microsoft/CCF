// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/extensions/extension_interface.h"
#include "js/tx_access.h"

#include <string_view>

namespace ccf::js::extensions
{
  class CcfConsoleExtension : public ExtensionInterface
  {
  public:
    CcfConsoleExtension() {}

    void install(js::core::Context& ctx) override;

    static void log_info_with_tag(
      const ccf::js::TxAccess access, std::string_view s);
  };
}
