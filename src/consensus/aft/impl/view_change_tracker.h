// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"

#include <chrono>
#include <map>
#include <set>

namespace aft
{
  class ViewChangeTracker
  {
    struct ViewChange
    {
      std::set<kv::NodeId> received_view_changes;
    };

  public:
    ViewChangeTracker(
      kv::NodeId my_node_id_,
      kv::Consensus::View current_view,
      std::chrono::milliseconds time_between_attempts_) :
      my_node_id(my_node_id_),
      last_view_change_sent(current_view),
      time_between_attempts(time_between_attempts_)
    {}

    bool should_send_view_change(
      std::chrono::milliseconds time)
    {
      if (
        time > time_between_attempts +
          time_previous_view_change_increment)
      {
        ViewChange vc;
        vc.received_view_changes.emplace(my_node_id);
        ++last_view_change_sent;
        view_changes.insert(std::pair<kv::Consensus::View, ViewChange>(
          last_view_change_sent, std::move(vc)));
        time_previous_view_change_increment = time;
        return true;
      }
      return false;
    }

    kv::Consensus::View get_target_view() const
    {
      return last_view_change_sent;
    }

    void set_current_view_change(kv::Consensus::View view)
    {
      view_changes.clear();
      last_view_change_sent = view;
    }

  private:
    kv::NodeId my_node_id;
    std::map<kv::Consensus::View, ViewChange> view_changes;
    std::chrono::milliseconds time_previous_view_change_increment =
      std::chrono::milliseconds(0);
    kv::Consensus::View last_view_change_sent = 0;
    const std::chrono::milliseconds time_between_attempts;
  };
}