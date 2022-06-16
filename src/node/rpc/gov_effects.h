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
      kv::Tx& tx, ServiceIdentities identities) override
    {
      impl.transition_service_to_open(tx, identities);
    }

    bool rekey_ledger(kv::Tx& tx) override
    {
      return impl.rekey_ledger(tx);
    }

    void trigger_recovery_shares_refresh(kv::Tx& tx) override
    {
      impl.trigger_recovery_shares_refresh(tx);
    }

    void trigger_ledger_chunk(kv::Tx& tx) override
    {
      impl.trigger_ledger_chunk(tx);
    }

    void trigger_snapshot(kv::Tx& tx) override
    {
      impl.trigger_snapshot(tx);
    }

    void trigger_acme_refresh(
      kv::Tx& tx,
      const std::optional<std::vector<std::string>>& interfaces =
        std::nullopt) override
    {
      impl.trigger_acme_refresh(tx, interfaces);
    }
  };
}