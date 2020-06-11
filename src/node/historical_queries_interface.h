// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"

#include <memory>

namespace ccf::historical
{
  using StorePtr = std::shared_ptr<kv::Store>;

  class AbstractStateCache
  {
  public:
    virtual ~AbstractStateCache() = default;

    virtual StorePtr get_store_at(consensus::Index idx) = 0;
  };

  class StubStateCache : public AbstractStateCache
  {
  public:
    StorePtr get_store_at(consensus::Index idx) override
    {
      return nullptr;
    }
  };
}