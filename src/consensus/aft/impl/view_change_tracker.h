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
      ViewChange(ccf::View view_) :
        view(view_),
        new_view_sent(false)
      {}

      ccf::View view;
      bool new_view_sent;

      std::map<ccf::NodeId, ccf::ViewChangeRequest> received_view_changes;
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
      return (time <=
              (time_between_attempts + time_previous_view_change_increment)) &&
        (time_previous_view_change_increment != std::chrono::milliseconds(0));
    }

    ccf::View get_target_view() const
    {
      return last_view_change_sent;
    }

    void set_current_view_change(ccf::View view)
    {
      view_changes.clear();
      last_view_change_sent = view;
    }

    void received_skip_view(const SkipViewMsg& r)
    {
      if (last_view_change_sent != r.view)
      {
        LOG_FAIL_FMT(
          "Received skip view message for not the latest view, "
          "last_view_change_sent:{}, r.view:{}",
          last_view_change_sent,
          r.view);
        return;
      }

      time_previous_view_change_increment = std::chrono::milliseconds(0);
    }

    enum class ResultAddView
    {
      OK,
      APPEND_NEW_VIEW_MESSAGE
    };

    ResultAddView add_request_view_change(
      ccf::ViewChangeRequest& v,
      const ccf::NodeId& from,
      ccf::View view,
      uint32_t node_count)
    {
      auto it = view_changes.find(view);
      if (it == view_changes.end())
      {
        ViewChange view_change(view);
        std::tie(it, std::ignore) =
          view_changes.emplace(view, std::move(view_change));
      }
      it->second.received_view_changes.emplace(from, v);

      if (
        should_send_new_view(
          it->second.received_view_changes.size(), node_count) &&
        it->second.new_view_sent == false)
      {
        it->second.new_view_sent = true;
        last_valid_view = view;
        return ResultAddView::APPEND_NEW_VIEW_MESSAGE;
      }

      return ResultAddView::OK;
    }

    ccf::SeqNo write_view_change_confirmation_append_entry(ccf::View view)
    {
      ccf::ViewChangeConfirmation nv =
        create_view_change_confirmation_msg(view, true);
      return store->write_view_change_confirmation(nv);
    }

    std::vector<uint8_t> get_serialized_view_change_confirmation(
      ccf::View view, bool force_create_new = false)
    {
      ccf::ViewChangeConfirmation nv =
        create_view_change_confirmation_msg(view, force_create_new);
      nlohmann::json j;
      to_json(j, nv);
      std::string s = j.dump();
      return {s.begin(), s.end() + 1};
    }

    bool add_unknown_primary_evidence(
      CBuffer data,
      ccf::View view,
      const ccf::NodeId& from,
      uint32_t node_count)
    {
      nlohmann::json j = nlohmann::json::parse(data.p);
      auto vc = j.get<ccf::ViewChangeConfirmation>();

      if (view != vc.view)
      {
        return false;
      }

      if (last_valid_view == vc.view)
      {
        return true;
      }

      if (!store->verify_view_change_request_confirmation(vc, from))
      {
        return false;
      }

      if (
        vc.view_change_messages.size() < ccf::get_message_threshold(node_count))
      {
        return false;
      }

      for (auto it : vc.view_change_messages)
      {
        if (!store->verify_view_change_request(
              it.second, it.first, vc.view, vc.seqno))
        {
          return false;
        }
      }

      last_valid_view = view;
      return true;
    }

    bool check_evidence(ccf::View view) const
    {
      return last_valid_view == view;
    }

    void clear(bool is_primary, ccf::View view)
    {
      for (auto it = view_changes.begin(); it != view_changes.end();)
      {
        if (is_primary && it->first != view)
        {
          it = view_changes.erase(it);
        }
        else
        {
          ++it;
        }
      }
      view_changes.clear();
      last_valid_view = view;
    }

  private:
    std::shared_ptr<ccf::ProgressTrackerStore> store;
    std::map<ccf::View, ViewChange> view_changes;
    std::chrono::milliseconds time_previous_view_change_increment =
      std::chrono::milliseconds(0);
    ccf::View last_view_change_sent = 0;
    ccf::View last_valid_view = aft::starting_view_change;
    const std::chrono::milliseconds time_between_attempts;
    ccf::ViewChangeConfirmation last_nvc;

    // TODO: add logging here
    ccf::ViewChangeConfirmation create_view_change_confirmation_msg(
      ccf::View view, bool force_create_new = false)
    {
      if (view == last_nvc.view && !force_create_new)
      {
        return last_nvc;
      }

      auto it = view_changes.find(view);
      if (it == view_changes.end())
      {
        LOG_FAIL_FMT(
          "Cannot write unknown view-change to ledger, view:{}", view);
        throw std::logic_error(fmt::format(
          "Cannot write unknown view-change to ledger, view:{}", view));
      }

      // TODO: fix this
      auto& vc = it->second;
      ccf::ViewChangeConfirmation nv(vc.view, 42);

      for (auto it : vc.received_view_changes)
      {
        LOG_INFO_FMT("Adding to view:{}, from:{}, seqno:{}", view, it.first, it.second.seqno);
        nv.view_change_messages.emplace(it.first, it.second);
      }

      last_nvc = nv;

      return nv;
    }

    bool should_send_new_view(size_t received_requests, size_t node_count) const
    {
      return received_requests == ccf::get_message_threshold(node_count);
    }
  };
}