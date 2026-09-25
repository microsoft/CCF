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

#ifdef CCF_RECOVERY_TRACE
#  include <map>
#  include <set>
#  include <string_view>
#endif

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

#ifdef CCF_RECOVERY_TRACE
  // What one execution of advance() read, wrote and requested. Trace only.
  struct AdvanceTrace
  {
    StateMachine pre = StateMachine::GOSSIPING;
    StateMachine pre_timeout = StateMachine::GOSSIPING;
    StateMachine post = StateMachine::GOSSIPING;
    StateMachine post_timeout = StateMachine::GOSSIPING;
    std::optional<std::map<sealing_recovery::Name, ccf::TxID>> gossips =
      std::nullopt;
    std::optional<std::set<sealing_recovery::Name>> votes = std::nullopt;
    std::optional<sealing_recovery::Name> chosen = std::nullopt;
    std::optional<OpenKinds> open_kind = std::nullopt;
    bool restart = false;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(AdvanceTrace);
  DECLARE_JSON_REQUIRED_FIELDS(
    AdvanceTrace, pre, pre_timeout, post, post_timeout);
  DECLARE_JSON_OPTIONAL_FIELDS(
    AdvanceTrace, gossips, votes, chosen, open_kind, restart);
#endif
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

    ds::Mutex recovery_decision_protocol_lock;
    std::optional<recovery_decision_protocol::RequestNodeInfo> node_info_cache;
    std::optional<recovery_decision_protocol::IAmOpenRequest>
      iamopen_request_cache;

  public:
    RecoveryDecisionProtocolSubsystem(NodeState* node_state);
    void reset_state(ccf::kv::Tx& tx);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(
      ccf::kv::Tx& tx,
      bool timeout
#ifdef CCF_RECOVERY_TRACE
      ,
      recovery_decision_protocol::AdvanceTrace& trace
#endif
    );

    recovery_decision_protocol::IAmOpenRequest& get_iamopen_request(
      kv::ReadOnlyTx& tx);

#ifdef CCF_RECOVERY_TRACE
    void record_trace_step(
      const char* kind,
      const nlohmann::json& params,
      std::string_view source,
      std::optional<ccf::TxID> txid,
      const recovery_decision_protocol::AdvanceTrace& trace) noexcept;
#endif

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
    sealing_recovery::Location& get_location();
    ccf::TxID get_last_recovered_signed_txid();

#ifdef CCF_RECOVERY_TRACE
    void record_trace_send(
      nlohmann::json& request,
      const char* message,
      const sealing_recovery::Name& target,
      std::optional<ccf::TxID> txid) noexcept;
    std::string emit_trace(nlohmann::json&& record);
#endif
  };
}
