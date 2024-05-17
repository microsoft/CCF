// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  class CcfGovEffectsExtension : public ExtensionInterface
  {
  public:
    kv::Tx* tx;

    CcfGovEffectsExtension(kv::Tx* t) : tx(t) {}

    void install(js::core::Context& ctx) override;
  };
}
