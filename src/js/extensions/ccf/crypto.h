// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/extensions/iextension.h"

namespace ccf::js::extensions
{
  class CcfCryptoExtension : public IExtension
  {
  public:
    CcfCryptoExtension() {}

    void install(js::core::Context& ctx) override;
  };
}
