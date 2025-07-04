// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.strToBuf
   * - ccf.bufToStr
   * - ccf.jsonCompatibleToBuf
   * - ccf.bufToJsonCompatible
   *
   * - ccf.pemToId
   * - ccf.tcbHexToPolicy
   *
   * - ccf.enableUntrustedDateTime
   * - ccf.enableMetricsLogging
   *
   **/
  class ConvertersExtension : public ExtensionInterface
  {
  public:
    ConvertersExtension() {}

    void install(js::core::Context& ctx) override;
  };
}
