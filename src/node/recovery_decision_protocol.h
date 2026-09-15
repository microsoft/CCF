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
    std::string message_id;
  };
  DECLARE_JSON_TYPE(TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(TaggedWithNodeInfo, info, message_id);

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
  struct AdvanceResult
  {
    StateMachine pre;
    StateMachine post;
    std::optional<OpenKinds> open_kind = std::nullopt;
  };

  struct Execution
  {
    std::optional<StateMachine> pre_state = std::nullopt;
    std::optional<uint64_t> trace_attempt = std::nullopt;
  };

  struct TraceEvent
  {
    std::string kind;
    std::optional<uint64_t> attempt = std::nullopt;
    std::optional<std::string> message_id = std::nullopt;
    std::optional<std::string> caused_by = std::nullopt;
    std::optional<sealing_recovery::Name> source = std::nullopt;
    std::optional<ccf::View> view = std::nullopt;
    std::optional<ccf::SeqNo> seqno = std::nullopt;
    std::optional<std::string> pre = std::nullopt;
    std::optional<std::string> post = std::nullopt;
    std::optional<std::string> open_kind = std::nullopt;
    std::optional<std::string> send = std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TraceEvent);
  DECLARE_JSON_REQUIRED_FIELDS(TraceEvent, kind);
  DECLARE_JSON_OPTIONAL_FIELDS(
    TraceEvent,
    attempt,
    message_id,
    caused_by,
    source,
    view,
    seqno,
    pre,
    post,
    open_kind,
    send);
#endif
}

namespace ccf
{
#ifdef CCF_RECOVERY_TRACE
  class CommitCallbackInterface;
  class RpcContext;
#endif
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

    ds::Mutex message_id_lock;
    uint64_t next_message_number = 0;
    std::string recovery_instance_id;
    std::string recovery_node;

#ifdef CCF_RECOVERY_TRACE
    ds::Mutex trace_lock;
    uint64_t next_trace_sequence = 0;
    uint64_t next_trace_message_number = 0;
    uint64_t next_trace_attempt = 0;
    std::vector<std::string> trace_expected_locations;
#endif

  public:
    RecoveryDecisionProtocolSubsystem(NodeState* node_state);
    void reset_state(ccf::kv::Tx& tx);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(
      ccf::kv::Tx& tx,
      bool timeout
#ifdef CCF_RECOVERY_TRACE
      ,
      recovery_decision_protocol::AdvanceResult& trace_result
#endif
    );

    recovery_decision_protocol::IAmOpenRequest& get_iamopen_request(
      kv::ReadOnlyTx& tx);

#ifdef CCF_RECOVERY_TRACE
    std::shared_ptr<recovery_decision_protocol::Execution>
    prepare_trace_execution(RpcContext& rpc_ctx) noexcept;
    void complete_trace_execution_locally(
      RpcContext& rpc_ctx,
      const ccf::TxID& txid,
      CommitCallbackInterface& commit_callbacks) noexcept;
    void abort_previous_trace_attempt(RpcContext& rpc_ctx) noexcept;
    void record_trace_receive(
      recovery_decision_protocol::Execution& execution,
      const std::string& kind,
      const std::string& caused_by,
      const std::string& source,
      const std::optional<ccf::TxID>& txid,
      recovery_decision_protocol::StateMachine pre,
      const recovery_decision_protocol::AdvanceResult& result) noexcept;
    void record_trace_timeout(
      recovery_decision_protocol::Execution& execution,
      const recovery_decision_protocol::AdvanceResult& result) noexcept;
#endif

  private:
    // Start path
    void start_message_retry_timers();
    void start_failover_timers();

    // Stop periodic tasks
    void stop_timers();
    void restart_after_commit();

    // Steady state operations
    recovery_decision_protocol::RequestNodeInfo& get_node_info(
      kv::ReadOnlyTx& tx);
    void send_gossip_unsafe(
      recovery_decision_protocol::GossipRequest request,
      recovery_decision_protocol::StateMachine state,
      const crypto::Pem& self_signed_node_cert,
      const crypto::Pem& node_private_key);
    void send_vote_unsafe(
      recovery_decision_protocol::TaggedWithNodeInfo request,
      const recovery_decision_protocol::NodeInfo& node_info,
      const crypto::Pem& self_signed_node_cert,
      const crypto::Pem& node_private_key);
    void send_iamopen_unsafe(
      recovery_decision_protocol::IAmOpenRequest request,
      const crypto::Pem& self_signed_node_cert,
      const crypto::Pem& node_private_key);

    RecoveryDecisionProtocolConfig& get_config();
    sealing_recovery::Location& get_location();
    ccf::TxID get_last_recovered_signed_txid();

    void initialise_protocol_instance(ccf::kv::ReadOnlyTx& tx);
    std::string new_message_id();

#ifdef CCF_RECOVERY_TRACE
    void initialise_trace() noexcept;
    void record_trace_effects(
      std::vector<recovery_decision_protocol::TraceEvent>& events,
      uint64_t attempt,
      recovery_decision_protocol::StateMachine pre,
      const recovery_decision_protocol::AdvanceResult& result);
    void emit_trace_event(
      recovery_decision_protocol::TraceEvent event) noexcept;
    void emit_trace_event_unsafe(recovery_decision_protocol::TraceEvent event);
    uint64_t new_trace_attempt_unsafe();
    std::string new_trace_message_id_unsafe();
    void emit_trace_send(
      const std::string& message_id,
      const std::string& message_kind,
      const sealing_recovery::Name& target,
      recovery_decision_protocol::StateMachine state,
      const std::optional<ccf::TxID>& txid = std::nullopt) noexcept;
#endif
  };
}
