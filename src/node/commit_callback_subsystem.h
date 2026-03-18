// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/impl/state.h"
#include "kv/kv_types.h"
#include "node/commit_callback_interface.h"

#include <map>
#include <mutex>

namespace ccf
{
  class CommitCallbackSubsystem : public CommitCallbackInterface
  {
  private:
    using Callbacks = std::vector<std::pair<ccf::TxID, CommitCallback>>;
    std::map<ccf::SeqNo, Callbacks> pending_callbacks;

    std::optional<ccf::TxID> known_commit = std::nullopt;
    aft::ViewHistory known_view_history;

    std::mutex callbacks_mutex;

    ccf::kv::Consensus* consensus = nullptr;

  public:
    CommitCallbackSubsystem() = default;

    void set_consensus(ccf::kv::Consensus* c)
    {
      consensus = c;
    }

    void add_callback(ccf::TxID tx_id, CommitCallback&& callback) override
    {
      std::optional<ccf::FinalTxStatus> immediate_status;

      {
        std::lock_guard<std::mutex> guard(callbacks_mutex);

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

    void trigger_callbacks(
      ccf::TxID committed, const aft::ViewHistory& view_history)
    {
      if (consensus == nullptr)
      {
        throw std::logic_error(
          "trigger_callbacks() called before set_consensus()");
      }

      // Collect callbacks to invoke, under the lock
      using ReadyCallback =
        std::tuple<ccf::TxID, ccf::FinalTxStatus, CommitCallback>;
      std::vector<ReadyCallback> ready;

      {
        std::lock_guard<std::mutex> guard(callbacks_mutex);

        known_commit = committed;
        known_view_history = view_history;

        auto it = pending_callbacks.begin();
        while (it != pending_callbacks.end())
        {
          auto& [seqno, callbacks] = *it;
          if (seqno > committed.seqno)
          {
            break;
          }

          for (auto& [tx_id, callback] : callbacks)
          {
            const auto local_view = view_history.view_at(tx_id.seqno);
            const auto status = ccf::evaluate_tx_status(
              tx_id.view,
              tx_id.seqno,
              local_view,
              committed.view,
              committed.seqno);

            if (status != TxStatus::Committed && status != TxStatus::Invalid)
            {
              throw std::logic_error(fmt::format(
                "Expected transaction {} evaluated against commit point {} to "
                "return terminal TxStatus, instead returned {}",
                tx_id.to_str(),
                committed.to_str(),
                nlohmann::json(status).dump()));
            }

            const auto final_status = static_cast<ccf::FinalTxStatus>(status);
            ready.emplace_back(
              std::move(tx_id), final_status, std::move(callback));
          }

          it = pending_callbacks.erase(it);
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
