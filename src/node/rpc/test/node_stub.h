// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/rpc/nodeinterface.h"

namespace ccf
{
  class StubNodeState : public ccf::AbstractNodeState
  {
    std::map<NodeId, std::vector<uint8_t>> joiners_fresh_keys;

    bool finish_recovery(Store::Tx& tx, const nlohmann::json& args) override
    {
      return true;
    }

    bool is_part_of_public_network() const override
    {
      return true;
    }

    bool is_primary() const override
    {
      return true;
    }

    void set_joiner_key(
      NodeId joiner_id, const std::vector<uint8_t>& raw_key) override
    {
      joiners_fresh_keys.emplace(joiner_id, raw_key);
    }
  };

  class StubNotifier : public ccf::AbstractNotifier
  {
    void notify(const std::vector<uint8_t>& data) override {}
  };
}