// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/rpc/node_interface.h"
#include "node/secret_share.h"

namespace ccf
{
  class StubNodeState : public ccf::AbstractNodeState
  {
  private:
    bool is_public = false;
    std::shared_ptr<NetworkTables> network;

  public:
    StubNodeState(std::shared_ptr<NetworkTables> network_ = nullptr) :
      network(network_)
    {}

    bool finish_recovery(
      Store::Tx& tx, const nlohmann::json& args, bool with_shares) override
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

    bool is_part_of_network() const override
    {
      return true;
    }

    void node_quotes(
      Store::Tx& tx,
      GetQuotes::Out& result,
      const std::optional<std::set<NodeId>>& filter) override
    {}

    bool split_ledger_secrets(Store::Tx& tx) override
    {
      auto [members_view, shares_view] =
        tx.get_view(network->members, network->shares);
      SecretSharing::SplitSecret secret_to_split = {};

      GenesisGenerator g(*network.get(), tx);
      auto active_member_count = g.get_active_members_count();
      size_t threshold = g.get_recovery_threshold();

      auto shares =
        SecretSharing::split(secret_to_split, active_member_count, threshold);

      // Here, shares are not encrypted and record in the ledger in plain text
      EncryptedSharesMap recorded_shares;
      MemberId member_id = 0;
      for (auto const& s : shares)
      {
        auto share_raw = std::vector<uint8_t>(s.begin(), s.end());
        recorded_shares[member_id] = {{}, share_raw};
        member_id++;
      }
      g.add_key_share_info({{}, recorded_shares});

      return true;
    }

    bool restore_ledger_secrets(
      Store::Tx& tx, const std::vector<SecretSharing::Share>& shares) override
    {
      return true;
    }

    NodeId get_node_id() const override
    {
      return 0;
    }

    void set_is_public(bool is_public_)
    {
      is_public = is_public_;
    }
  };

  class StubNotifier : public ccf::AbstractNotifier
  {
    void notify(const std::vector<uint8_t>& data) override {}
  };
}