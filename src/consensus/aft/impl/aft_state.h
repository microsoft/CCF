// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "replica.h"

#include <map>
#include <set>

namespace aft
{
  struct ServiceState
  {
    ServiceState(kv::NodeId my_node_id_) :
      my_node_id(my_node_id_),
      current_view(0),
      last_committed_version(0),
      network_state(NetworkState::not_open)
    {}

    kv::NodeId my_node_id;
    kv::Consensus::View current_view;
    kv::Version last_committed_version;

    std::map<kv::NodeId, std::shared_ptr<Replica>> configuration;
    SpinLock configuration_lock;

    enum class NetworkState
    {
      not_open = 0,
      open
    } network_state;
    std::set<kv::NodeId> received_open_network_messages;
  };
}