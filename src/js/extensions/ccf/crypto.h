// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  class CryptoExtension : public ExtensionInterface
  {
  public:
    CryptoExtension() {}

    void install(js::core::Context& ctx) override;
  };
}
