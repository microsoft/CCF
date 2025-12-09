// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "ccf/js/tx_access.h"

#include <string_view>

namespace ccf::js::extensions
{
  /** Adds the following functions to the global object:
   *
   * - console.log
   * - console.info
   * - console.warn
   * - console.error
   *
   * These redirect to the CCF logging macros, based on the current TxAccess (ie
   * - app vs gov)
   **/

  class ConsoleExtension : public ExtensionInterface
  {
  public:
    ConsoleExtension() = default;

    void install(js::core::Context& ctx) override;

    static void log_info_with_tag(ccf::js::TxAccess access, std::string_view s);
  };
}
