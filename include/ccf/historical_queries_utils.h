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

  // Modifies the receipt stored in state to include historical service
  // endorsements, where required. If the state talks about a different service
  // identity, which is known to be a predecessor of this service (via disaster
  // recoveries), then an endorsement chain of all service identities preceding
  // the current one will be created. This may need to use the state_cache to
  // request additional historical entries to construct this endorsement, and
  // may read from the current/latest state via tx. Returns true if the
  // operation is complete, though it may still have failed to produce an
  // endorsement. Returns false if additional entries have been requested, in
  // which case the caller should retry later.
  bool populate_cose_service_endorsements(
    ccf::kv::ReadOnlyTx& tx,
    ccf::historical::StatePtr& state,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem);

  // Verifies CCF COSE receipt issued by either current service identity or the
  // one from the past that both corresponds to the receipt Tx ID and can be
  // trusted via back-endorsement chain.
  void verify_self_issued_receipt(
    const std::vector<uint8_t>& cose_receipt,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem);
}
