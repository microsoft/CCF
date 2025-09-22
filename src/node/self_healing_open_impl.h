// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/self_heal_open.h"
#include "ccf/tx.h"
#include "self_healing_open_types.h"

namespace ccf
{
  class NodeState;
  class SelfHealingOpenService
  {
  private:
    // SelfHealingOpenService is solely owned by NodeState
    std::weak_ptr<NodeState> weak_node_state;

  public:
    SelfHealingOpenService(std::shared_ptr<NodeState> node_state) : weak_node_state(node_state) {}
    void try_start(ccf::kv::Tx& tx, bool recovering);
    void advance(ccf::kv::Tx& tx, bool timeout);

  private:
    struct SHOMsg
    {
      SHOMsg(SelfHealingOpenService& self_) : self(self_) {}
      SelfHealingOpenService& self;
    };

    // Start path
    void start_message_retry_timers();
    void start_failover_timers(ccf::kv::Tx& tx);

    // Steady state operations
    self_healing_open::RequestNodeInfo make_node_info();
    void send_gossip_unsafe();
    void send_vote_unsafe(const SelfHealingOpenNodeInfo_t&);
    void send_iamopen_unsafe();
  };
}