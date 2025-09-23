// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/node/startup_config.h"
#include "ccf/service/tables/self_healing_open.h"
#include "ccf/tx.h"

namespace ccf::self_healing_open
{
  struct RequestNodeInfo
  {
    QuoteInfo quote_info;
    std::string published_network_address;
    std::string intrinsic_id;
    std::string service_identity;
  };
  DECLARE_JSON_TYPE(RequestNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestNodeInfo,
    quote_info,
    published_network_address,
    intrinsic_id,
    service_identity);

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
  DECLARE_JSON_TYPE(GossipRequest);
  DECLARE_JSON_REQUIRED_FIELDS(GossipRequest, txid);
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

  public:
    SelfHealingOpenSubsystem(NodeState* node_state);
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(ccf::kv::Tx& tx, bool timeout);

  private:
    struct SHOMsg
    {
      SHOMsg(SelfHealingOpenSubsystem& self_) : self(self_) {}
      SelfHealingOpenSubsystem& self;
    };

    // Start path
    void start_message_retry_timers();
    void start_failover_timers();

    // Steady state operations
    self_healing_open::RequestNodeInfo make_node_info();
    void send_gossip_unsafe();
    void send_vote_unsafe(const SelfHealingOpenNodeInfo&);
    void send_iamopen_unsafe();
  };
}