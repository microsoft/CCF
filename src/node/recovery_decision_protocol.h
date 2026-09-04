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
#ifdef CCF_RECOVERY_TRACE
    std::optional<std::string> trace_message_id = std::nullopt;
#endif
  };
#ifdef CCF_RECOVERY_TRACE
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(TaggedWithNodeInfo, info);
  DECLARE_JSON_OPTIONAL_FIELDS(TaggedWithNodeInfo, trace_message_id);
#else
  DECLARE_JSON_TYPE(TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(TaggedWithNodeInfo, info);
#endif

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

    ds::Mutex recovery_decision_protocol_lock;
    std::optional<recovery_decision_protocol::RequestNodeInfo> node_info_cache;
    std::optional<recovery_decision_protocol::IAmOpenRequest>
      iamopen_request_cache;

#ifdef CCF_RECOVERY_TRACE
    ds::Mutex trace_lock;
    uint64_t next_trace_record_id = 0;
    uint64_t next_trace_sequence = 0;
    uint64_t next_trace_message_number = 0;
    std::string trace_instance_id;
    std::vector<std::string> trace_expected_locations;
    std::string trace_node;
    std::string trace_committed_state;
#endif

  public:
    RecoveryDecisionProtocolSubsystem(NodeState* node_state);
    void reset_state(ccf::kv::Tx& tx);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(ccf::kv::Tx& tx, bool timeout);

    recovery_decision_protocol::IAmOpenRequest& get_iamopen_request(
      kv::ReadOnlyTx& tx);

#ifdef CCF_RECOVERY_TRACE
    recovery_decision_protocol::StateMachine get_trace_state(
      kv::ReadOnlyTx& tx);
    void record_trace_receive(
      ccf::kv::Tx& tx,
      const std::string& kind,
      const std::optional<std::string>& caused_by,
      const std::string& source,
      const std::optional<ccf::TxID>& txid,
      recovery_decision_protocol::StateMachine pre);
    void record_trace_timeout(
      ccf::kv::Tx& tx, recovery_decision_protocol::StateMachine pre);
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

#ifdef CCF_RECOVERY_TRACE
    void initialise_trace(ccf::kv::Tx& tx);
    void record_trace_event(
      ccf::kv::Tx& tx, recovery_decision_protocol::TraceEvent event);
    void record_trace_effects(
      ccf::kv::Tx& tx,
      recovery_decision_protocol::StateMachine pre,
      recovery_decision_protocol::StateMachine post);
    void emit_trace_event(recovery_decision_protocol::TraceEvent event);
    void emit_trace_event_unsafe(recovery_decision_protocol::TraceEvent event);
    std::string new_trace_message_id();
    std::string new_trace_message_id_unsafe();
    void emit_trace_send_unsafe(
      const std::string& message_id,
      const std::string& description,
      const std::optional<ccf::TxID>& txid = std::nullopt);
#endif
  };
}
