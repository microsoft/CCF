// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/locking.h"
#include "consensus/aft/commit_observer.h"
#include "consensus/aft/impl/state.h"
#include "node/commit_callback_interface.h"

#include <map>

namespace ccf
{
  class CommitCallbackSubsystem : public CommitCallbackInterface,
                                  public aft::CommitObserver
  {
  private:
    using Callbacks = std::vector<std::pair<ccf::TxID, CommitCallback>>;
    ccf::ds::Mutex callbacks_mutex;
    std::map<ccf::SeqNo, Callbacks> pending_callbacks
      CCF_GUARDED_BY(callbacks_mutex);

    std::optional<ccf::TxID> known_commit CCF_GUARDED_BY(callbacks_mutex) =
      std::nullopt;
    aft::ViewHistory known_view_history CCF_GUARDED_BY(callbacks_mutex);

  public:
    CommitCallbackSubsystem() = default;

    // Terminal cleanup after workers stop. Release sessions waiting for a
    // commit which will never arrive, without invoking their callbacks.
    void shutdown()
    {
      decltype(pending_callbacks) abandoned;
      {
        ccf::ds::MutexGuard guard(callbacks_mutex);
        abandoned.swap(pending_callbacks);
      }
    }

    void add_callback(ccf::TxID tx_id, CommitCallback&& callback) override
    {
      std::optional<ccf::FinalTxStatus> immediate_status;

      {
        ccf::ds::MutexGuard guard(callbacks_mutex);

        if (known_commit.has_value())
        {
          const auto local_view = known_view_history.view_at(tx_id.seqno);
          const auto status = ccf::evaluate_tx_status(
            tx_id.view,
            tx_id.seqno,
            local_view,
            known_commit->view,
            known_commit->seqno);

          if (status == TxStatus::Committed || status == TxStatus::Invalid)
          {
            immediate_status = static_cast<ccf::FinalTxStatus>(status);
          }
        }

        if (!immediate_status.has_value())
        {
          pending_callbacks[tx_id.seqno].emplace_back(
            std::make_pair(tx_id, std::move(callback)));
          return;
        }
      }

      // Terminal status determined from cached state - execute callback
      // outside the lock
      callback(tx_id, immediate_status.value());
    }

    void on_commit(
      ccf::TxID committed, const aft::ViewHistory& view_history) override
    {
      // Collect callbacks to invoke, under the lock
      using ReadyCallback =
        std::tuple<ccf::TxID, ccf::FinalTxStatus, CommitCallback>;
      std::vector<ReadyCallback> ready;

      {
        ccf::ds::MutexGuard guard(callbacks_mutex);

        const bool view_advanced =
          !known_commit.has_value() || committed.view > known_commit->view;
        known_commit = committed;
        known_view_history = view_history;

        auto it = pending_callbacks.begin();
        while (it != pending_callbacks.end())
        {
          auto& [seqno, callbacks] = *it;
          // Beyond the commit point, only transactions from views before the
          // committed view are terminal (Invalid). Unless the committed view
          // advanced, these were dispatched by an earlier commit or on
          // registration.
          if (seqno > committed.seqno && !view_advanced)
          {
            break;
          }

          auto remaining = callbacks.begin();
          for (auto cb = callbacks.begin(); cb != callbacks.end(); ++cb)
          {
            auto& [tx_id, callback] = *cb;
            const auto local_view = view_history.view_at(tx_id.seqno);
            const auto status = ccf::evaluate_tx_status(
              tx_id.view,
              tx_id.seqno,
              local_view,
              committed.view,
              committed.seqno);

            if (status == TxStatus::Committed || status == TxStatus::Invalid)
            {
              const auto final_status = static_cast<ccf::FinalTxStatus>(status);
              ready.emplace_back(tx_id, final_status, std::move(callback));
            }
            else if (seqno <= committed.seqno)
            {
              throw std::logic_error(fmt::format(
                "Expected transaction {} evaluated against commit point {} to "
                "return terminal TxStatus, instead returned {}",
                tx_id.to_str(),
                committed.to_str(),
                nlohmann::json(status).dump()));
            }
            else
            {
              if (remaining != cb)
              {
                *remaining = std::move(*cb);
              }
              ++remaining;
            }
          }
          callbacks.erase(remaining, callbacks.end());

          if (callbacks.empty())
          {
            it = pending_callbacks.erase(it);
          }
          else
          {
            ++it;
          }
        }
      }

      // Execute callbacks outside the lock
      for (auto& [tx_id, final_status, callback] : ready)
      {
        callback(tx_id, final_status);
      }
    }
  };
}
