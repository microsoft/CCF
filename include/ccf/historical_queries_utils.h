// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/network_identity_interface.h"
#include "ccf/rpc_context.h"
#include "ccf/tx.h"

namespace ccf::historical
{
  // Modifies the receipt stored in state to include historical service
  // endorsements, where required. If the state talks about a different service
  // identity, which is known to be a predecessor of this service (via disaster
  // recoveries), then an endorsement of the receipt's node certificate will be
  // created. This may need to use the state_cache to request additional
  // historical entries to construct this endorsement, and may read from the
  // current/latest state via tx. Returns true if the operation is complete,
  // though it may still have failed to produce an endorsement. Returns false if
  // additional entries have been requested, in which case the caller should
  // retry later.
  bool populate_service_endorsements(
    ccf::kv::ReadOnlyTx& tx,
    ccf::historical::StatePtr& state,
    AbstractStateCache& state_cache,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem);

  // TO DO interface
  // Same as above? True if complete no matter if endorsement was produced,
  // false if in progress
  bool populate_cose_service_endorsements(
    ccf::kv::ReadOnlyTx& tx, // TO DO check needed
    ccf::historical::StatePtr& state, // TO DO check needed
    AbstractStateCache& state_cache, // TO DO check needed
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem // TO DO check needed
  );
}