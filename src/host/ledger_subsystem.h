// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "ds/worker_shutdown_gate.h"
#include "host/ledger.h"
#include "node/rpc/ledger_interface.h"
#include "tasks/basic_task.h"
#include "tasks/ordered_tasks.h"
#include "tasks/task_system.h"

#include <filesystem>
#include <mutex>
#include <optional>

namespace asynchost
{
  // Typed, task-backed ledger access for the node. All mutations and reads of
  // mutable (uncommitted) state run in FIFO order on a single OrderedTasks
  // lane. Reads which lie wholly within committed files run as ordinary tasks
  // and may overlap with each other and with the lane: nothing in the lane
  // modifies a file once it has been classified as committed (see init and
  // open below). No action in this class blocks on another task.
  class LedgerSubsystem : public ccf::AbstractLedgerSubsystemInterface
  {
  private:
    Ledger& ledger;
    const size_t max_read_size;

    ccf::tasks::JobBoard& job_board;
    std::shared_ptr<ccf::tasks::OrderedTasks> ordered_tasks;

    std::shared_ptr<ccf::ds::WorkerShutdownGate> shutdown_gate =
      std::make_shared<ccf::ds::WorkerShutdownGate>();
    std::once_flag shutdown_once;

    // Enqueues fn on the ordered lane. Returns false, without enqueuing, once
    // shutdown has begun. Queued work that starts after shutdown is skipped
    // without touching storage.
    template <typename F>
    bool submit_ordered(std::string name, F&& fn)
    {
      if (shutdown_gate->is_shutting_down())
      {
        return false;
      }

      auto gate = shutdown_gate;
      ordered_tasks->add_action(ccf::tasks::make_basic_action(
        [gate, name, fn = std::forward<F>(fn)]() mutable {
          if (!gate->try_register())
          {
            LOG_DEBUG_FMT(
              "Skipping {} because the ledger subsystem is shutting down",
              name);
            return;
          }

          ccf::ds::WorkerShutdownGate::UnregisterGuard guard{gate};
          fn();
        },
        std::move(name)));
      return true;
    }

    static ::consensus::LedgerRangeResult make_range_result(
      ::consensus::Index from,
      ::consensus::Index requested_to,
      std::optional<LedgerReadResult>&& read_result)
    {
      if (!read_result.has_value())
      {
        return {
          from, requested_to, ::consensus::LedgerRangeStatus::NotFound, {}};
      }

      if (read_result->limit_exceeded)
      {
        return {
          from, requested_to, ::consensus::LedgerRangeStatus::TooLarge, {}};
      }

      return {
        from,
        read_result->end_idx,
        ::consensus::LedgerRangeStatus::Found,
        std::move(read_result->data)};
    }

    ::consensus::LedgerRangeResult read_mutable_range(
      ::consensus::Index from, ::consensus::Index to)
    {
      return make_range_result(
        from,
        to,
        ledger.read_entries_with_limit_status(from, to, max_read_size));
    }

    // Static so the committed-read task does not need this object alive.
    static ::consensus::LedgerRangeResult read_committed_range(
      Ledger& ledger_,
      ::consensus::Index from,
      ::consensus::Index to,
      size_t max_read_size_)
    {
      return make_range_result(
        from, to, ledger_.read_committed_entries(from, to, max_read_size_));
    }

  public:
    // Tests may supply a caller-driven job board for deterministic execution.
    LedgerSubsystem(
      Ledger& ledger_,
      size_t max_read_size_,
      ccf::tasks::JobBoard& job_board_ = ccf::tasks::get_main_job_board()) :
      ledger(ledger_),
      max_read_size(max_read_size_),
      job_board(job_board_),
      ordered_tasks(
        ccf::tasks::OrderedTasks::create(job_board, "Ledger operations"))
    {}

    ~LedgerSubsystem() override
    {
      shutdown();
    }

    bool init(
      ::consensus::Index idx, ::consensus::Index recovery_start_idx) override
    {
      // init un-commits files after idx so they can be replayed into. It also
      // lowers the committed classification boundary, so no read dispatched
      // after this action can target those files concurrently.
      return submit_ordered("Ledger init", [this, idx, recovery_start_idx]() {
        ledger.init(idx, recovery_start_idx);
      });
    }

    bool append(std::vector<uint8_t>&& entry, bool committable) override
    {
      return submit_ordered(
        "Ledger append", [this, entry = std::move(entry), committable]() {
          ledger.write_entry(entry.data(), entry.size(), committable);
        });
    }

    bool truncate(::consensus::Index idx, bool recovery_mode) override
    {
      return submit_ordered("Ledger truncate", [this, idx, recovery_mode]() {
        ledger.truncate(idx, recovery_mode);
        if (recovery_mode)
        {
          ledger.set_recovery_start_idx(idx);
        }
      });
    }

    bool commit(::consensus::Index idx) override
    {
      return submit_ordered(
        "Ledger commit", [this, idx]() { ledger.commit(idx); });
    }

    bool open() override
    {
      // open renames committed recovery files. Those are never classified as
      // committed (they stay in Ledger::files until now), so every read of
      // them runs in this lane and is already ordered against this action.
      return submit_ordered(
        "Ledger open", [this]() { ledger.complete_recovery(); });
    }

    bool get_range(
      ::consensus::Index from,
      ::consensus::Index to,
      ::consensus::LedgerRangeCallback&& callback) override
    {
      // Classification runs on the lane so it observes every earlier commit.
      return submit_ordered(
        "Ledger range classification",
        [this, from, to, callback = std::move(callback)]() mutable {
          if (!ledger.is_in_committed_file(to))
          {
            callback(read_mutable_range(from, to));
            return;
          }

          job_board.add_task(ccf::tasks::make_basic_task(
            [gate = shutdown_gate,
             ledger_ = &ledger,
             from,
             to,
             read_size = max_read_size,
             callback = std::move(callback)]() mutable {
              if (!gate->try_register())
              {
                LOG_DEBUG_FMT(
                  "Skipping committed ledger read {} to {} because the ledger "
                  "subsystem is shutting down",
                  from,
                  to);
                return;
              }

              ccf::ds::WorkerShutdownGate::UnregisterGuard guard{gate};
              callback(read_committed_range(*ledger_, from, to, read_size));
            },
            "Committed ledger read"));
        });
    }

    [[nodiscard]] std::optional<std::filesystem::path>
    committed_ledger_path_with_idx(size_t idx) override
    {
      return ledger.committed_ledger_path_with_idx(idx);
    }

    [[nodiscard]] size_t get_init_idx() override
    {
      return ledger.get_init_idx();
    }

    // Rejects new submissions and waits for in-flight storage actions and
    // callbacks. Idempotent.
    void shutdown() override
    {
      std::call_once(
        shutdown_once, [this]() { shutdown_gate->shutdown_and_wait(); });
    }
  };
}
