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

    void transition_service_to_open(kv::Tx& tx) override
    {
      impl.transition_service_to_open(tx);
    }

    bool rekey_ledger(kv::Tx& tx) override
    {
      return impl.rekey_ledger(tx);
    }

    void trigger_recovery_shares_refresh(kv::Tx& tx) override
    {
      impl.trigger_recovery_shares_refresh(tx);
    }

    void request_ledger_chunk(kv::Tx& tx) override
    {
      impl.request_ledger_chunk(tx);
    }

    // TODO: You don't live here!
    void trigger_host_process_launch(
      const std::vector<std::string>& args) override
    {
      impl.trigger_host_process_launch(args);
    }
  };
}