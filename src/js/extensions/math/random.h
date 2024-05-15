// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/extensions/iextension.h"

namespace ccf::js::extensions
{
  // Implements Math.random in an enclave-compatible way
  class MathRandomExtension : public IExtension
  {
  public:
    MathRandomExtension() {}

    void install(js::core::Context& ctx) override;
  };
}
