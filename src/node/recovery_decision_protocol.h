// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/node/startup_config.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/recovery_decision_protocol.h"
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
  class NodeState;
  class RecoveryDecisionProtocolSubsystem
  {
  private:
    // RecoveryDecisionProtocolSubsystem is solely owned by NodeState, and all
    // tasks should finish before NodeState is destroyed
    NodeState* node_state;

    // Periodic task handles - kept to allow cancellation
    ccf::tasks::Task retry_task;
    ccf::tasks::Task failover_task;

    pal::Mutex recovery_decision_protocol_lock;
    std::optional<recovery_decision_protocol::RequestNodeInfo> node_info_cache;
    std::optional<recovery_decision_protocol::IAmOpenRequest>
      iamopen_request_cache;

  public:
    RecoveryDecisionProtocolSubsystem(NodeState* node_state);
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

    RecoveryDecisionProtocolConfig& get_config();
    recovery_decision_protocol::Location& get_location();
    ccf::TxID get_last_recovered_signed_txid();
  };
}
