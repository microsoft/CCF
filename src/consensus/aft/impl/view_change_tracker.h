// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "node/view_change.h"

#include <chrono>
#include <map>
#include <set>

namespace aft
{
  class ViewChangeTracker
  {
    struct ViewChange
    {
      ViewChange(
        kv::Consensus::View view_,
        kv::Consensus::SeqNo seqno_) :
        view(view_), seqno(seqno_), new_view_sent(false)
      {}

      kv::Consensus::View view;
      kv::Consensus::SeqNo seqno;
      bool new_view_sent;

      std::map<kv::NodeId, ccf::ViewChange>
        received_view_changes;
    };

  public:
    ViewChangeTracker(
      std::shared_ptr<ccf::ProgressTrackerStore> store_,
      std::chrono::milliseconds time_between_attempts_) :
      store(store_),
      last_view_change_sent(0),
      time_between_attempts(time_between_attempts_)
    {}

    bool should_send_view_change(std::chrono::milliseconds time)
    {
      if (time > time_between_attempts + time_previous_view_change_increment)
      {
        ++last_view_change_sent;
        time_previous_view_change_increment = time;
        return true;
      }
      return false;
    }

    bool is_view_change_in_progress(std::chrono::milliseconds time)
    {
      return time <=
        (time_between_attempts + time_previous_view_change_increment);
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

    enum class ResultAddView
    {
      OK,
      APPEND_NEW_VIEW_MESSAGE
    };
    
    ResultAddView add_request_view_change(ccf::ViewChange& v,
      kv::NodeId from,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      uint32_t node_count)
    {
      auto it = view_changes.find(view);
      if (it == view_changes.end())
      {
        ViewChange view_change(view, seqno);
        std::tie(it, std::ignore) = view_changes.emplace(
          view, std::move(view_change));
      }
      it->second.received_view_changes.emplace(from, v);

      if (
        should_send_new_view(
          it->second.received_view_changes.size(), node_count) &&
        it->second.new_view_sent == false)
      {
        it->second.new_view_sent = true;
        return ResultAddView::APPEND_NEW_VIEW_MESSAGE;
      }

      return ResultAddView::OK;
    }

    void write_new_view_append_entry(kv::Consensus::View view)
    {
      auto it = view_changes.find(view);
      if (it == view_changes.end())
      {
        throw std::logic_error(fmt::format(
          "Cannot write unknown view-change to ledger, view:{}", view));
      }

      auto& vc = it->second;
      ccf::NewView nv(vc.view, vc.seqno);

      for (auto it : vc.received_view_changes)
      {
        nv.view_change_messages.emplace(it.first, it.second);
      }
      
      store->write_new_view(nv);
    }
    
    void clear()
    {
        view_changes.clear();
    }
    
  private:
    std::shared_ptr<ccf::ProgressTrackerStore> store;
    std::map<kv::Consensus::View, ViewChange> view_changes;
    std::chrono::milliseconds time_previous_view_change_increment =
      std::chrono::milliseconds(0);
    kv::Consensus::View last_view_change_sent = 0;
    const std::chrono::milliseconds time_between_attempts;

    // TODO: this should not be duplicated
    uint32_t get_message_threshold(uint32_t node_count) const
    {
      uint32_t f = 0;
      for (; 3 * f + 1 < node_count; ++f)
        ;

      return 2 * f + 1;
    }

    bool should_send_new_view(size_t received_requests, size_t node_count) const
    {
      return received_requests ==  get_message_threshold(node_count);
    }

  };
}