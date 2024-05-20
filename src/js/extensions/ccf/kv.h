// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "js/extensions/extension_interface.h"

#include <memory>

namespace ccf::js::extensions
{
  /**
   * Adds ccf.kv object, containing an index[] operator to return views over
   * single maps.
   *
   **/
  class KvExtension : public ExtensionInterface
  {
  public:
    struct Impl;

    std::unique_ptr<Impl> impl;

    KvExtension(kv::Tx* t);
    ~KvExtension();

    void install(js::core::Context& ctx);
  };
}