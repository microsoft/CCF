// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/aft_types.h"
#include "startup_state_machine.h"
#include "ds/ccf_exception.h"
#include "replica.h"

namespace aft
{
  class StateMachine : public IStateMachine
  {
  public:
    StateMachine(
      kv::NodeId my_node_id_,
      const std::vector<uint8_t>& cert,
      std::unique_ptr<IStartupStateMachine> startup_state_machine_) :
      my_node_id(my_node_id_),
      current_view(0),
      is_network_open(false),
      startup_state_machine(std::move(startup_state_machine_))
    {
      add_node(my_node_id, cert);
    }

    void receive_request(std::unique_ptr<RequestMessage> request) override
    {
      LOG_INFO_FMT("BBBBBBBBBBBBBBBB");
      if (!is_network_open)
      {
        LOG_INFO_FMT("BBBBBBBBBBBBBBBB");
        startup_state_machine->receive_request(std::move(request));
        return;
      }
      LOG_INFO_FMT("BBBBBBBBBBBBBBBB");

      ccf::ccf_logic_error("Not Implemented");
      // TODO: fill this in when we open the network
    }

    void add_node(kv::NodeId node_id, const std::vector<uint8_t>& cert) override
    {
      std::lock_guard<std::mutex> lock(configuration_lock);
      configuration.emplace(node_id, std::make_unique<Replica>(node_id, cert));
    }

    bool is_primary() override
    {
      return my_node_id == primary();
    }

    kv::NodeId primary() override
    {
      std::lock_guard<std::mutex> lock(configuration_lock);
      return current_view % configuration.size();
    }

    virtual kv::Consensus::View view() override
    {
      return current_view;
    }

    private:
      kv::NodeId my_node_id;
      kv::Consensus::View current_view;
      bool is_network_open;
      std::unique_ptr<IStartupStateMachine> startup_state_machine;

      std::map<kv::NodeId, std::unique_ptr<Replica>> configuration;
      SpinLock configuration_lock;


  };
}