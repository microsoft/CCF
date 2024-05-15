// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "js/extensions/iextension.h"

#include <memory>

namespace ccf::js::extensions
{
  class CcfKvExtension : public IExtension
  {
  public:
    struct Impl;

    std::unique_ptr<Impl> impl;

    CcfKvExtension(kv::Tx* t);
    ~CcfKvExtension();

    void install(js::core::Context& ctx);
  };
}