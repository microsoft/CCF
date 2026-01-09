// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/node/startup_config.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/self_healing_open.h"
#include "ccf/tx.h"
#include "tasks/task.h"

namespace ccf::self_healing_open
{
  struct RequestNodeInfo
  {
    QuoteInfo quote_info;
    Identity identity;
    std::string service_identity;
  };
  DECLARE_JSON_TYPE(RequestNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestNodeInfo, quote_info, identity, service_identity);

  struct TaggedWithNodeInfo
  {
  public:
    RequestNodeInfo info;
  };
  DECLARE_JSON_TYPE(TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(TaggedWithNodeInfo, info);

  struct GossipRequest : public TaggedWithNodeInfo
  {
    ccf::kv::Version txid{};
  };
  DECLARE_JSON_TYPE_WITH_BASE(GossipRequest, TaggedWithNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(GossipRequest, txid);

  struct IAmOpenRequest : public TaggedWithNodeInfo
  {
    std::string prev_service_fingerprint;
    ccf::kv::Version txid{};
  };
}

namespace ccf
{
  class NodeState;
  class SelfHealingOpenSubsystem
  {
  private:
    // SelfHealingOpenService is solely owned by NodeState, and all tasks should
    // finish before NodeState is destroyed
    NodeState* node_state;

    // Periodic task handles - kept to allow cancellation
    ccf::tasks::Task retry_task;
    ccf::tasks::Task failover_task;

    pal::Mutex self_healing_open_lock;
    std::optional<self_healing_open::IAmOpenRequest> iamopen_request_cache;

  public:
    SelfHealingOpenSubsystem(NodeState* node_state);
    void reset_state(ccf::kv::Tx& tx);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(ccf::kv::Tx& tx, bool timeout);

    self_healing_open::IAmOpenRequest& get_iamopen_request(kv::ReadOnlyTx& tx);

  private:
    // Start path
    void start_message_retry_timers();
    void start_failover_timers();

    // Stop periodic tasks
    void stop_timers();

    // Steady state operations
    self_healing_open::RequestNodeInfo make_node_info(kv::ReadOnlyTx& tx);
    void send_gossip_unsafe(kv::ReadOnlyTx& tx);
    void send_vote_unsafe(
      kv::ReadOnlyTx& tx, const self_healing_open::NodeInfo& node_info);
    void send_iamopen_unsafe(kv::ReadOnlyTx& tx);

    SelfHealingOpenConfig& get_config();
  };
}