// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/ds/locking.h"
#include "ccf/endpoints/endpoint_context.h"
#include "ccf/kv/tx.h"
#include "ccf/service/tables/self_healing_open.h"
#include "ccf/tx_id.h"
#include "node/configuration.h"
#include "tasks/task.h"

#include <atomic>
#include <string_view>

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

  // Validated join target ready to log and trigger restart once committed.
  struct JoinTarget
  {
    sealing_recovery::Location location;
    std::string service_cert_pem;
    std::string service_fingerprint;
  };

  // What one execution of advance() read, wrote and decided. Only join_target
  // is acted on, once the execution's transaction commits, and only the rest
  // is traced.
  struct AdvanceTrace
  {
    StateMachine pre = StateMachine::GOSSIPING;
    StateMachine pre_timeout = StateMachine::GOSSIPING;
    StateMachine post = StateMachine::GOSSIPING;
    StateMachine post_timeout = StateMachine::GOSSIPING;
    std::optional<sealing_recovery::Name> chosen = std::nullopt;
    std::optional<OpenKinds> open_kind = std::nullopt;
    bool restart = false;
    // The node to restart and join, set together with restart
    std::optional<JoinTarget> join_target = std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(AdvanceTrace);
  DECLARE_JSON_REQUIRED_FIELDS(
    AdvanceTrace, pre, pre_timeout, post, post_timeout);
  DECLARE_JSON_OPTIONAL_FIELDS(AdvanceTrace, chosen, open_kind, restart);
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
    std::atomic<uint64_t> next_trace_sequence = 0;
    std::atomic<uint64_t> next_trace_batch = 0;

  public:
    RecoveryDecisionProtocolSubsystem(NodeState* node_state);
    void reset_state(ccf::kv::Tx& tx);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(
      ccf::kv::Tx& tx,
      bool timeout,
      recovery_decision_protocol::AdvanceTrace& trace);

    recovery_decision_protocol::IAmOpenRequest& get_iamopen_request(
      kv::ReadOnlyTx& tx);

    // A handler execution is recorded here, and on_step_committed traces it
    // once its transaction commits locally and schedules any restart it decided
    // on for global commit. An execution that conflicts is run again, so it
    // must have no other effect
    void prepare_step(
      ccf::RpcContext& rpc_ctx,
      const char* kind,
      std::string_view source,
      std::optional<ccf::TxID> txid,
      const recovery_decision_protocol::AdvanceTrace& trace);
    void on_step_committed(
      ccf::endpoints::CommandEndpointContext& ctx, const ccf::TxID& txid);

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
    // Records the send in the trace, then dispatches it
    void dispatch_authenticated_message(
      const nlohmann::json& request,
      const sealing_recovery::Location& target,
      const std::string& endpoint,
      const crypto::Pem& self_signed_node_cert,
      const crypto::Pem& privkey_pem);

    RecoveryDecisionProtocolConfig& get_config();
    sealing_recovery::Location& get_location();
    ccf::TxID get_last_recovered_signed_txid();

    void record_trace_send(
      const std::string& message,
      const sealing_recovery::Name& target,
      const nlohmann::json& request) noexcept;
    void emit_trace(nlohmann::json&& record);
  };
}
