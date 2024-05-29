// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "ccf/tx.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.refreshAppBytecodeCache
   * - ccf.setJwtPublicSigningKeys
   * - ccf.removeJwtPublicSigningKeys
   *
   * These should potentially be moved to a nested object, but are retained here
   * for backwards compatibility.
   *
   **/
  class GovEffectsExtension : public ExtensionInterface
  {
  public:
    kv::Tx* tx;

    GovEffectsExtension(kv::Tx* t) : tx(t) {}

    void install(js::core::Context& ctx) override;
  };
}
