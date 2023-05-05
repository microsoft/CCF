// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/historical_queries_interface.h"
#include "ccf/network_identity_interface.h"
#include "ccf/rpc_context.h"
#include "ccf/tx.h"

namespace ccf::historical
{
  bool get_service_endorsements(
    kv::ReadOnlyTx& tx,
    ccf::historical::StatePtr& state,
    AbstractStateCache& state_cache,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem);
}