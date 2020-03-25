// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/secret_share.h"
#include "node_call_types.h"

namespace ccf
{
  class AbstractNodeState
  {
  public:
    virtual ~AbstractNodeState() {}
    virtual bool finish_recovery(
      Store::Tx& tx, const nlohmann::json& args, bool with_shares) = 0;
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

    virtual bool split_ledger_secrets(Store::Tx& tx) = 0;
    virtual bool restore_ledger_secrets(
      Store::Tx& tx, const std::vector<SecretSharing::Share>& shares) = 0;
  };
}
