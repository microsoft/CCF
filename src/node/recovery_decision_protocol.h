// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/locking.h"
#include "ccf/node/startup_config.h"
#include "ccf/service/tables/self_healing_open.h"
#include "ccf/tx.h"
#include "ccf/tx_id.h"
#include "tasks/task.h"

namespace ccf::recovery_decision_protocol
{
  struct TaggedWithNodeInfo
  {
  public:
    RequestNodeInfo info;
  };
  DECLARE_JSON_TYPE(TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(TaggedWithNodeInfo, info);

  struct GossipRequest : public TaggedWithNodeInfo
  {
    ccf::TxID txid{};
  };
  DECLARE_JSON_TYPE_WITH_BASE(GossipRequest, TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(GossipRequest, txid);

  struct IAmOpenRequest : public TaggedWithNodeInfo
  {
    std::string prev_service_fingerprint;
    ccf::TxID txid{};
  };

  DECLARE_JSON_TYPE_WITH_BASE(IAmOpenRequest, TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(IAmOpenRequest, prev_service_fingerprint, txid);
}

namespace ccf
{
  namespace kv
  {
    class Store;
  }

  class AbstractGovernanceEffects;

  class AbstractRecoveryDecisionProtocolNode
  {
  public:
    virtual ~AbstractRecoveryDecisionProtocolNode() = default;
    virtual NodeId get_node_id() const = 0;
    virtual void cache_node_info(
      std::optional<recovery_decision_protocol::RequestNodeInfo>& cache,
      const QuoteInfo& quote_info) = 0;
    virtual crypto::Pem get_self_signed_certificate() = 0;
    virtual crypto::Pem get_private_key() = 0;
    virtual TxID get_last_recovered_signed_txid() = 0;
    virtual void restart() = 0;
  };

  class RecoveryDecisionProtocolSubsystem
  {
  private:
    // The owner must keep these dependencies alive and finish all tasks before
    // destroying the subsystem. Retain references to configuration and store
    // slots, which are populated after NodeState construction.
    const std::optional<SealingRecoveryConfig>& sealing_recovery;
    const std::shared_ptr<kv::Store>& tables;
    AbstractGovernanceEffects& governance;
    AbstractRecoveryDecisionProtocolNode& node;

    // Periodic task handles - kept to allow cancellation
    ccf::tasks::Task retry_task;
    ccf::tasks::Task failover_task;

    ds::Mutex recovery_decision_protocol_lock;
    std::optional<recovery_decision_protocol::RequestNodeInfo> node_info_cache;
    std::optional<recovery_decision_protocol::IAmOpenRequest>
      iamopen_request_cache;

  public:
    RecoveryDecisionProtocolSubsystem(
      const std::optional<SealingRecoveryConfig>& sealing_recovery,
      const std::shared_ptr<kv::Store>& tables,
      AbstractGovernanceEffects& governance,
      AbstractRecoveryDecisionProtocolNode& node);
    void reset_state(ccf::kv::Tx& tx);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(ccf::kv::Tx& tx, bool timeout);

    recovery_decision_protocol::IAmOpenRequest& get_iamopen_request(
      kv::ReadOnlyTx& tx);

  private:
    // Start path
    void start_message_retry_timers();
    void start_failover_timers();

    // Stop periodic tasks
    void stop_timers();

    // Steady state operations
    recovery_decision_protocol::RequestNodeInfo& get_node_info(
      kv::ReadOnlyTx& tx);
    void send_gossip_unsafe(kv::ReadOnlyTx& tx);
    void send_vote_unsafe(
      kv::ReadOnlyTx& tx,
      const recovery_decision_protocol::NodeInfo& node_info);
    void send_iamopen_unsafe(kv::ReadOnlyTx& tx);

    const RecoveryDecisionProtocolConfig& get_config();
    const sealing_recovery::Location& get_location();
  };
}
