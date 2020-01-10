// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/rpc/nodeinterface.h"

namespace ccf
{
  class StubNodeState : public ccf::AbstractNodeState
  {
    bool finish_recovery(Store::Tx& tx, const nlohmann::json& args) override
    {
      return true;
    }

    bool open_network(Store::Tx& tx) override
    {
      return true;
    }

    bool rekey_ledger(Store::Tx& tx) override
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

    bool is_reading_public_ledger() const override
    {
      return false;
    }

    bool is_reading_private_ledger() const override
    {
      return false;
    }

    bool is_part_of_network() const override
    {
      return true;
    }

    void node_quotes(Store::Tx& tx, GetQuotes::Out& result) override {}
  };

  class StubNotifier : public ccf::AbstractNotifier
  {
    void notify(const std::vector<uint8_t>& data) override {}
  };
}