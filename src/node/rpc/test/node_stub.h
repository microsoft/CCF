// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/rpc/node_interface.h"
#include "node/share_manager.h"

namespace ccf
{
  class StubNodeState : public ccf::AbstractNodeState
  {
  private:
    bool is_public = false;
    ShareManager& share_manager;

  public:
    StubNodeState(ShareManager& share_manager) : share_manager(share_manager) {}

    bool accept_recovery(kv::Tx& tx) override
    {
      return true;
    }

    bool rekey_ledger(kv::Tx& tx) override
    {
      return true;
    }

    bool is_part_of_public_network() const override
    {
      return is_public;
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

    bool is_verifying_snapshot() const override
    {
      return false;
    }

    bool is_part_of_network() const override
    {
      return true;
    }

    void initiate_private_recovery(kv::Tx& tx) override
    {
      share_manager.restore_recovery_shares_info(tx, {});
    }

    kv::Version get_last_recovered_signed_idx() override
    {
      return kv::NoVersion;
    }

    NodeId get_node_id() const override
    {
      return 0;
    }

    void set_is_public(bool is_public_)
    {
      is_public = is_public_;
    }

    ExtendedState state() override
    {
      return {State::partOfNetwork, {}, {}};
    }

    void open_user_frontend() override{};
  };
}