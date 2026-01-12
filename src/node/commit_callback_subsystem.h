// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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

    // Use a recursive mutex so that `add_callback` may safely be called while a
    // callback is executing (and the mutex is locked)
    std::recursive_mutex callbacks_mutex;

    ccf::kv::Consensus* consensus = nullptr;

  public:
    CommitCallbackSubsystem() = default;

    void set_consensus(ccf::kv::Consensus* c)
    {
      consensus = c;
    }

    void add_callback(ccf::TxID tx_id, CommitCallback&& callback) override
    {
      std::lock_guard<std::recursive_mutex> guard(callbacks_mutex);

      if (known_commit.has_value() && consensus != nullptr)
      {
        const auto status =
          consensus->evaluate_tx_status(tx_id.view, tx_id.seqno);

        if (status == TxStatus::Committed || status == TxStatus::Invalid)
        {
          // TxID is already known to be in a terminal state - execute callback
          // immediately
          const auto final_status = static_cast<ccf::FinalTxStatus>(status);
          callback(tx_id, final_status);
          return;
        }
      }

      pending_callbacks[tx_id.seqno].emplace_back(
        std::make_pair(tx_id, std::move(callback)));
    }

    void trigger_callbacks(ccf::TxID committed)
    {
      if (consensus == nullptr)
      {
        throw std::logic_error(
          "trigger_callbacks() called before set_consensus()");
      }

      std::lock_guard<std::recursive_mutex> guard(callbacks_mutex);

      known_commit = committed;

      auto it = pending_callbacks.begin();
      while (it != pending_callbacks.end())
      {
        auto [seqno, callbacks] = *it;
        if (seqno > committed.seqno)
        {
          break;
        }

        // Have committed to this seqno - terminal status for this transaction
        // should now be known
        for (auto& [tx_id, callback] : callbacks)
        {
          const auto status =
            consensus->evaluate_tx_status(tx_id.view, tx_id.seqno);

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
          callback(tx_id, final_status);
        }

        it = pending_callbacks.erase(it);
      }
    }
  };
}
