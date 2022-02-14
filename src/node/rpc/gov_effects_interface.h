// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"

namespace ccf
{
  class AbstractGovernanceEffects
  {
  public:
    virtual ~AbstractGovernanceEffects() = default;

    virtual void transition_service_to_open(kv::Tx& tx) = 0;
    virtual bool rekey_ledger(kv::Tx& tx) = 0;
    virtual void trigger_recovery_shares_refresh(kv::Tx& tx) = 0;
    virtual void request_ledger_chunk(kv::Tx& tx) = 0;

    // TODO: You don't live here!
    virtual void trigger_host_process_launch(
      const std::vector<std::string>& args) = 0;
  };
}