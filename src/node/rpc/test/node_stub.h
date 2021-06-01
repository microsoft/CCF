// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "kv/test/stub_consensus.h"
#include "node/rpc/node_interface.h"
#include "node/share_manager.h"

namespace ccf
{
  class StubNodeState : public ccf::AbstractNodeState
  {
  private:
    bool is_public = false;

  public:
    void transition_service_to_open(kv::Tx& tx) override
    {
      return;
    }

    bool rekey_ledger(kv::Tx& tx) override
    {
      return true;
    }

    void trigger_recovery_shares_refresh(kv::Tx& tx) override
    {
      return;
    }

    void trigger_host_process_launch(
      const std::vector<std::string>& args) override
    {
      return;
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
      throw std::logic_error("Unimplemented");
    }

    kv::Version get_last_recovered_signed_idx() override
    {
      return kv::NoVersion;
    }

    NodeId get_node_id() const override
    {
      return kv::test::PrimaryNodeId;
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

    QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der) override
    {
      return QuoteVerificationResult::Verified;
    }

    std::optional<kv::Version> get_startup_snapshot_seqno() override
    {
      return std::nullopt;
    }

    SessionMetrics get_session_metrics() override
    {
      return {};
    }
  };

  class StubNodeStateCache : public historical::AbstractStateCache
  {
  public:
    void set_default_expiry_duration(
      historical::ExpiryDuration seconds_until_expiry)
    {}

    historical::StorePtr get_store_at(
      historical::RequestHandle handle,
      ccf::SeqNo seqno,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return nullptr;
    }

    historical::StorePtr get_store_at(
      historical::RequestHandle handle, ccf::SeqNo seqno)
    {
      return nullptr;
    }

    historical::StatePtr get_state_at(
      historical::RequestHandle handle, ccf::SeqNo seqno)
    {
      return nullptr;
    }

    std::vector<historical::StorePtr> get_store_range(
      historical::RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return {};
    }

    std::vector<historical::StorePtr> get_store_range(
      historical::RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno)
    {
      return {};
    }

    bool drop_request(historical::RequestHandle handle)
    {
      return true;
    }
  };

  struct StubNodeContext : public ccfapp::AbstractNodeContext
  {
  public:
    StubNodeState state = {};
    StubNodeStateCache cache = {};

    ccf::historical::AbstractStateCache& get_historical_state()
    {
      return cache;
    }

    StubNodeState& get_node_state()
    {
      return state;
    }
  };

  class StubRecoverableNodeState : public StubNodeState
  {
  private:
    ShareManager& share_manager;

  public:
    StubRecoverableNodeState(ShareManager& sm) : share_manager(sm) {}

    void initiate_private_recovery(kv::Tx& tx) override
    {
      kv::Version current_ledger_secret_version = 1;
      RecoveredEncryptedLedgerSecrets recovered_secrets;
      recovered_secrets.push_back(
        EncryptedLedgerSecretInfo{std::nullopt, current_ledger_secret_version});

      share_manager.restore_recovery_shares_info(
        tx, std::move(recovered_secrets));
    }
  };

  struct StubRecoverableNodeContext : public ccfapp::AbstractNodeContext
  {
  public:
    StubRecoverableNodeState state;
    StubNodeStateCache cache = {};

    StubRecoverableNodeContext(ShareManager& sm) : state(sm) {}

    ccf::historical::AbstractStateCache& get_historical_state()
    {
      return cache;
    }

    StubRecoverableNodeState& get_node_state()
    {
      return state;
    }
  };
}