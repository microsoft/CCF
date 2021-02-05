// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "node/rpc/endpoint_registry.h"

#include <chrono>
#include <memory>

namespace ccf::historical
{
  using StorePtr = std::shared_ptr<kv::Store>;

  // TODO: Proper docs
  // You get one active request per-handle. You can set timeout per-handle, and
  // drop a handle. Mostly you make a request (for a single Store or range of
  // Stores) with a handle. If you re-use an existing handle, it overwrites the
  // old request (but retains any metadata (expiry time)? Or uses default
  // metadata?)
  using RequestHandle = size_t;

  using ExpiryDuration = std::chrono::seconds;

  class AbstractStateCache
  {
  public:
    virtual ~AbstractStateCache() = default;

    virtual void set_default_expiry_duration(ExpiryDuration duration) = 0;

    virtual StorePtr get_store_at(
      RequestHandle handle,
      consensus::Index idx,
      ExpiryDuration expire_after) = 0;

    // Uses default expiry duration
    virtual StorePtr get_store_at(RequestHandle handle, consensus::Index idx) = 0;

    // Returns false if the handle is unknown
    virtual bool drop_request(RequestHandle handle) = 0;
  };
}