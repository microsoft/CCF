// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/share_manager.h"
#include "node_call_types.h"

namespace ccf
{
  class AbstractNodeState
  {
  public:
    virtual ~AbstractNodeState() {}
    virtual bool accept_recovery(Store::Tx& tx) = 0;
    virtual bool open_network(Store::Tx& tx) = 0;
    virtual bool rekey_ledger(Store::Tx& tx) = 0;
    virtual bool is_part_of_public_network() const = 0;
    virtual bool is_primary() const = 0;
    virtual bool is_reading_public_ledger() const = 0;
    virtual bool is_reading_private_ledger() const = 0;
    virtual bool is_part_of_network() const = 0;
    virtual void node_quotes(
      Store::Tx& tx,
      GetQuotes::Out& result,
      const std::optional<std::set<NodeId>>& filter = std::nullopt) = 0;
    virtual NodeId get_node_id() const = 0;

    virtual kv::Version get_last_recovered_commit_idx() = 0;
    // TODO: Can call share_manager directly
    virtual bool split_ledger_secrets(Store::Tx& tx) = 0;

    virtual ShareManager& get_share_manager() = 0;

    virtual void restore_ledger_secrets(Store::Tx& tx) = 0;
  };
}
