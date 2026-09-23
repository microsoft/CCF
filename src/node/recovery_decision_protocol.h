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
  // Trace-only observations. They are collected from protocol state that the
  // implementation reads or writes anyway, and are only logged.
  struct TraceGossip
  {
    sealing_recovery::Name location;
    ccf::View view = 0;
    ccf::SeqNo seqno = 0;

    bool operator==(const TraceGossip&) const = default;
  };
  DECLARE_JSON_TYPE(TraceGossip);
  DECLARE_JSON_REQUIRED_FIELDS(TraceGossip, location, view, seqno);

  // What a single execution of advance() read, wrote, and requested
  struct AdvanceTrace
  {
    StateMachine pre = StateMachine::GOSSIPING;
    StateMachine pre_timeout = StateMachine::GOSSIPING;
    StateMachine post = StateMachine::GOSSIPING;
    StateMachine post_timeout = StateMachine::GOSSIPING;
    std::optional<std::vector<TraceGossip>> gossips = std::nullopt;
    std::optional<std::vector<sealing_recovery::Name>> votes = std::nullopt;
    std::optional<sealing_recovery::Name> chosen = std::nullopt;
    std::optional<OpenKinds> open_kind = std::nullopt;
    bool restart = false;
    bool complete = false;
  };

  struct TraceEvent
  {
    std::string kind;
    std::optional<uint64_t> attempt = std::nullopt;
    std::optional<uint64_t> batch = std::nullopt;
    std::optional<sealing_recovery::Name> source = std::nullopt;
    std::optional<ccf::View> view = std::nullopt;
    std::optional<ccf::SeqNo> seqno = std::nullopt;
    std::optional<uint64_t> version = std::nullopt;
    std::optional<std::string> pre = std::nullopt;
    std::optional<std::string> post = std::nullopt;
    std::optional<std::string> pre_timeout = std::nullopt;
    std::optional<std::string> post_timeout = std::nullopt;
    std::optional<std::vector<TraceGossip>> gossips = std::nullopt;
    std::optional<std::vector<sealing_recovery::Name>> votes = std::nullopt;
    std::optional<sealing_recovery::Name> chosen = std::nullopt;
    std::optional<std::string> open_kind = std::nullopt;
    std::optional<std::string> send = std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TraceEvent);
  DECLARE_JSON_REQUIRED_FIELDS(TraceEvent, kind);
  DECLARE_JSON_OPTIONAL_FIELDS(
    TraceEvent,
    attempt,
    batch,
    source,
    view,
    seqno,
    version,
    pre,
    post,
    pre_timeout,
    post_timeout,
    gossips,
    votes,
    chosen,
    open_kind,
    send);
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

#ifdef CCF_RECOVERY_TRACE
    ds::Mutex trace_lock;
    std::string trace_instance;
    std::string trace_node;
    std::vector<sealing_recovery::Name> trace_expected_locations;
    uint64_t next_trace_sequence = 0;
    uint64_t next_trace_attempt = 0;
    uint64_t next_trace_batch = 0;
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
      recovery_decision_protocol::AdvanceTrace& trace
#endif
    );

    recovery_decision_protocol::IAmOpenRequest& get_iamopen_request(
      kv::ReadOnlyTx& tx);

#ifdef CCF_RECOVERY_TRACE
    std::optional<recovery_decision_protocol::StateMachine> read_trace_phase(
      kv::ReadOnlyTx& tx) noexcept;
    void record_trace_receive(
      std::string_view kind,
      const sealing_recovery::Name& source,
      const std::optional<ccf::TxID>& gossip_txid,
      std::optional<recovery_decision_protocol::StateMachine> pre,
      const recovery_decision_protocol::AdvanceTrace& trace) noexcept;
    void record_trace_timeout(
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
    void send_gossip_unsafe(
      kv::ReadOnlyTx& tx
#ifdef CCF_RECOVERY_TRACE
      ,
      uint64_t trace_batch
#endif
    );
    void send_vote_unsafe(
      kv::ReadOnlyTx& tx,
      const recovery_decision_protocol::NodeInfo& node_info
#ifdef CCF_RECOVERY_TRACE
      ,
      uint64_t trace_batch
#endif
    );
    void send_iamopen_unsafe(
      kv::ReadOnlyTx& tx
#ifdef CCF_RECOVERY_TRACE
      ,
      uint64_t trace_batch
#endif
    );

    RecoveryDecisionProtocolConfig& get_config();
    sealing_recovery::Location& get_location();
    ccf::TxID get_last_recovered_signed_txid();

#ifdef CCF_RECOVERY_TRACE
    void record_trace_start() noexcept;
    void record_trace_committed(
      ccf::kv::Version version,
      const std::optional<recovery_decision_protocol::StateMachine>&
        phase) noexcept;
    uint64_t record_trace_retry(
      recovery_decision_protocol::StateMachine phase) noexcept;
    void record_trace_send(
      uint64_t batch,
      const std::string& message_kind,
      const sealing_recovery::Name& target,
      const std::optional<ccf::TxID>& gossip_txid) noexcept;
    void record_trace_attempt(
      recovery_decision_protocol::TraceEvent&& event,
      recovery_decision_protocol::StateMachine pre,
      const recovery_decision_protocol::AdvanceTrace& trace);
    void emit_trace_events_unsafe(
      std::vector<recovery_decision_protocol::TraceEvent>&& events);
#endif
  };
}
