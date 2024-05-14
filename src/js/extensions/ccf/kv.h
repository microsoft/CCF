// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "js/extensions/iextension.h"
#include "kv/untyped_map.h"

#include <map>

namespace ccf::js::extensions
{
  class CcfKvExtension : public IExtension
  {
  public:
    kv::Tx* tx;
    std::unordered_map<std::string, kv::untyped::Map::Handle*> kv_handles = {};

    CcfKvExtension(kv::Tx* t) : tx(t) {}

    void install(js::core::Context& ctx);
  };
}