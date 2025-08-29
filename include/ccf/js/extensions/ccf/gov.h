// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.gov.isValidConstitution
   *
   **/
  class GovExtension : public ExtensionInterface
  {
  public:
    GovExtension() = default;

    void install(js::core::Context& ctx) override;
  };
}
