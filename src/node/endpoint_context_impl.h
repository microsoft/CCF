// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_context.h"
#include "kv/committable_tx.h"

namespace ccf
{
  // Implementation of EndpointContext, private to the framework (not visible
  // to user apps)
  struct EndpointContextImpl : public ccf::endpoints::EndpointContext
  {
    std::unique_ptr<ccf::kv::CommittableTx> owned_tx = nullptr;

    EndpointContextImpl(
      const std::shared_ptr<ccf::RpcContext>& r,
      std::unique_ptr<ccf::kv::CommittableTx> t) :
      ccf::endpoints::EndpointContext(r, *t),
      owned_tx(std::move(t))
    {}
  };
}
