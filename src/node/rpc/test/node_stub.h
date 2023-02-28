// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/node/host_processes_interface.h"
#include "kv/test/stub_consensus.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/node_interface.h"
#include "node/rpc/node_operation_interface.h"
#include "node/share_manager.h"

namespace ccf
{
  class StubNodeOperation : public ccf::AbstractNodeOperation
  {
  public:
    bool is_public = false;

    ExtendedState state() override
    {
      return {NodeStartupState::partOfNetwork, {}, {}};
    }

    bool is_in_initialised_state() const override
    {
      return false;
    }

    bool is_part_of_public_network() const override
    {
      return is_public;
    }

    bool is_part_of_network() const override
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

    bool can_replicate() override
    {
      return true;
    }

    kv::Version get_last_recovered_signed_idx() override
    {
      return kv::NoVersion;
    }

    SessionMetrics get_session_metrics() override
    {
      return {};
    }

    size_t get_jwt_attempts() override
    {
      return 0;
    }

    QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      pal::PlatformAttestationMeasurement& measurement) override
    {
      return QuoteVerificationResult::Verified;
    }

    kv::Version get_startup_snapshot_seqno() override
    {
      return 0;
    }

    void initiate_private_recovery(kv::Tx& tx) override
    {
      throw std::logic_error("Unimplemented");
    }

    crypto::Pem get_self_signed_node_certificate() override
    {
      return {};
    }
  };

  class StubGovernanceEffects : public ccf::AbstractGovernanceEffects
  {
  public:
    void transition_service_to_open(kv::Tx& tx, ServiceIdentities) override
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

    void trigger_ledger_chunk(kv::Tx& tx) override
    {
      return;
    }

    void trigger_snapshot(kv::Tx& tx) override
    {
      return;
    }

    void trigger_acme_refresh(
      kv::Tx& tx,
      const std::optional<std::vector<std::string>>& interfaces =
        std::nullopt) override
    {
      return;
    }
  };

  class StubHostProcesses : public ccf::AbstractHostProcesses
  {
  public:
    void trigger_host_process_launch(
      const std::vector<std::string>& args) override
    {
      return;
    }
  };

  class StubNodeStateCache : public historical::AbstractStateCache
  {
  public:
    void set_default_expiry_duration(
      historical::ExpiryDuration seconds_until_expiry)
    {}

    void track_deletes_on_missing_keys(bool track) {}

    kv::ReadOnlyStorePtr get_store_at(
      historical::RequestHandle handle,
      ccf::SeqNo seqno,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return nullptr;
    }

    kv::ReadOnlyStorePtr get_store_at(
      historical::RequestHandle handle, ccf::SeqNo seqno)
    {
      return nullptr;
    }

    historical::StatePtr get_state_at(
      historical::RequestHandle handle,
      ccf::SeqNo seqno,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return nullptr;
    }

    historical::StatePtr get_state_at(
      historical::RequestHandle handle, ccf::SeqNo seqno)
    {
      return nullptr;
    }

    std::vector<kv::ReadOnlyStorePtr> get_store_range(
      historical::RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return {};
    }

    std::vector<kv::ReadOnlyStorePtr> get_store_range(
      historical::RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno)
    {
      return {};
    }

    std::vector<historical::StatePtr> get_state_range(
      historical::RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return {};
    }

    std::vector<historical::StatePtr> get_state_range(
      historical::RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno)
    {
      return {};
    }

    std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      historical::RequestHandle handle,
      const SeqNoCollection& seqnos,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return {};
    }

    std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      historical::RequestHandle handle, const SeqNoCollection& seqnos)
    {
      return {};
    }

    std::vector<historical::StatePtr> get_states_for(
      historical::RequestHandle handle,
      const SeqNoCollection& seqnos,
      historical::ExpiryDuration seconds_until_expiry)
    {
      return {};
    }

    std::vector<historical::StatePtr> get_states_for(
      historical::RequestHandle handle, const SeqNoCollection& seqnos)
    {
      return {};
    }

    bool drop_cached_states(historical::RequestHandle handle)
    {
      return true;
    }
  };

  struct StubNodeContext : public ccfapp::AbstractNodeContext
  {
  public:
    std::shared_ptr<StubNodeOperation> node_operation = nullptr;
    std::shared_ptr<StubGovernanceEffects> gov_effects = nullptr;
    std::shared_ptr<StubHostProcesses> host_processes = nullptr;
    std::shared_ptr<StubNodeStateCache> cache = nullptr;

    StubNodeContext()
    {
      node_operation = std::make_shared<StubNodeOperation>();
      install_subsystem(node_operation);

      gov_effects = std::make_shared<StubGovernanceEffects>();
      install_subsystem(gov_effects);

      host_processes = std::make_shared<StubHostProcesses>();
      install_subsystem(host_processes);

      cache = std::make_shared<StubNodeStateCache>();
      install_subsystem(cache);
    }

    ccf::NodeId get_node_id() const override
    {
      return kv::test::PrimaryNodeId;
    }
  };
}