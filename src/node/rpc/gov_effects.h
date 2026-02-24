// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/node_state.h"
#include "node/rpc/gov_effects_interface.h"

namespace ccf
{
  class GovernanceEffects : public AbstractGovernanceEffects
  {
  protected:
    AbstractNodeState& impl;

  public:
    GovernanceEffects(AbstractNodeState& impl_) : impl(impl_) {}

    void transition_service_to_open(
      ccf::kv::Tx& tx, ServiceIdentities identities) override
    {
      impl.transition_service_to_open(tx, identities);
    }

    bool rekey_ledger(ccf::kv::Tx& tx) override
    {
      return impl.rekey_ledger(tx);
    }

    void trigger_recovery_shares_refresh(ccf::kv::Tx& tx) override
    {
      impl.trigger_recovery_shares_refresh(tx);
    }

    void trigger_ledger_chunk(ccf::kv::Tx& tx) override
    {
      impl.trigger_ledger_chunk(tx);
    }

    void trigger_snapshot(ccf::kv::Tx& tx) override
    {
      impl.trigger_snapshot(tx);
    }

    void shuffle_sealed_shares(ccf::kv::Tx& tx) override
    {
      impl.shuffle_sealed_shares(tx);
    }
  };
}