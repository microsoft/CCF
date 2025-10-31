// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
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

    struct ServiceIdentities
    {
      std::optional<ccf::crypto::Pem> previous;
      ccf::crypto::Pem next;
    };

    virtual void transition_service_to_open(
      ccf::kv::Tx& tx, ServiceIdentities identities) = 0;
    virtual bool rekey_ledger(ccf::kv::Tx& tx) = 0;
    virtual void trigger_recovery_shares_refresh(ccf::kv::Tx& tx) = 0;
    virtual void trigger_ledger_chunk(ccf::kv::Tx& tx) = 0;
    virtual void trigger_snapshot(ccf::kv::Tx& tx) = 0;
  };
}