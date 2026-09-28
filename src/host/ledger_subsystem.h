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

#include <atomic>
#include <filesystem>
#include <mutex>
#include <optional>
#include <thread>

namespace asynchost
{
  // Typed, task-backed ledger access for the node. All mutations and reads of
  // mutable (uncommitted) state run in FIFO order on a single OrderedTasks
  // lane. Reads which lie wholly within committed files are dispatched as
  // ordinary tasks so they do not hold up the lane; the Ledger's own state
  // lock still serialises their file access against mutations, as it did
  // when these reads ran on the libuv threadpool. No action in this class
  // blocks on another task.
  class LedgerSubsystem : public ccf::AbstractLedgerSubsystemInterface
  {
  private:
    Ledger& ledger;
    const size_t max_read_size;

    ccf::tasks::JobBoard& job_board;
    std::shared_ptr<ccf::tasks::OrderedTasks> ordered_tasks;

    std::shared_ptr<ccf::ds::WorkerShutdownGate> shutdown_gate =
      std::make_shared<ccf::ds::WorkerShutdownGate>();
    // Set at the start of shutdown(), before the lane is drained. Rejects new
    // submissions and suppresses read callbacks, while still letting queued
    // mutations reach disk.
    std::shared_ptr<std::atomic<bool>> draining =
      std::make_shared<std::atomic<bool>>(false);
    std::once_flag shutdown_once;

    // Enqueues fn on the ordered lane. Returns false, without enqueuing, once
    // shutdown has begun. Queued work that starts after shutdown is skipped
    // without touching storage.
    template <typename F>
    bool submit_ordered(std::string name, F&& fn)
    {
      if (draining->load() || shutdown_gate->is_shutting_down())
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

    // Runs fn after every mutation submitted before this call, and before any
    // submitted after it. Returns false, without running fn, once shutdown has
    // begun.
    //
    // Used by the node-to-node transport: AppendEntries framing on the host
    // must observe the appends the node submitted ahead of it.
    template <typename F>
    bool run_in_mutation_order(std::string name, F&& fn)
    {
      return submit_ordered(std::move(name), std::forward<F>(fn));
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
          if (draining->load())
          {
            // A read answered during shutdown would have its receiver submit
            // further work (recovery reads the next batch from its callback),
            // and the receiver may itself be tearing down. Drop it, as the
            // old design dropped responses the enclave had stopped reading.
            LOG_DEBUG_FMT(
              "Skipping ledger read {} to {} because the ledger subsystem is "
              "shutting down",
              from,
              to);
            return;
          }

          if (!ledger.is_in_committed_file(to))
          {
            callback(read_mutable_range(from, to));
            return;
          }

          job_board.add_task(ccf::tasks::make_basic_task(
            [gate = shutdown_gate,
             is_draining = draining,
             ledger_ = &ledger,
             from,
             to,
             read_size = max_read_size,
             callback = std::move(callback)]() mutable {
              if (is_draining->load() || !gate->try_register())
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

    // Completes mutations already accepted, then rejects new submissions and
    // waits for in-flight storage actions and callbacks. Idempotent.
    //
    // The caller must ensure no task worker can be executing the lane when
    // this is called; the host calls it after the enclave threads have
    // joined. Draining here is what the old design achieved by reading the
    // remaining ringbuffer messages before stopping the loop: a mutation which
    // append() or commit() accepted must reach disk. Queued reads are skipped
    // and their callbacks never fire: answering them would run receiver code
    // (and, for recovery, submit further reads) on this thread after the
    // enclave has stopped.
    void shutdown() override
    {
      std::call_once(shutdown_once, [this]() {
        draining->store(true);

        size_t pending = 0;
        bool active = false;
        bool paused = false;
        ordered_tasks->get_queue_summary(pending, active, paused);
        while (pending > 0 || active)
        {
          if (active)
          {
            std::this_thread::yield();
          }
          else
          {
            ordered_tasks->do_task();
          }
          ordered_tasks->get_queue_summary(pending, active, paused);
        }
        shutdown_gate->shutdown_and_wait();
      });
    }
  };
}
