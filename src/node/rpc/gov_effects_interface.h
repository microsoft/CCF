// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "ccf/tx.h"

namespace ccf
{
  class AbstractGovernanceEffects : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractGovernanceEffects() = default;

    static char const* get_subsystem_name()
    {
      return "GovernanceEffects";
    }

    virtual void transition_service_to_open(kv::Tx& tx) = 0;
    virtual bool rekey_ledger(kv::Tx& tx) = 0;
    virtual void trigger_recovery_shares_refresh(kv::Tx& tx) = 0;
    virtual void request_ledger_chunk(kv::Tx& tx) = 0;
  };
}