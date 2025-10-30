// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/thread_manager.h"

#include "tasks/worker.h"

#include <thread>

namespace ccf::tasks
{
  struct ThreadManager::PImpl
  {
    // Align by cacheline to avoid false sharing
    static constexpr size_t CACHELINE_SIZE = 64;

    template <typename T>
    struct alignas(CACHELINE_SIZE) CacheLineAligned
    {
      T value;
    };

    using StopSignal = CacheLineAligned<std::atomic<bool>>;

    static constexpr size_t MAX_WORKERS = 64;

    std::thread workers[MAX_WORKERS] = {};
    StopSignal stop_signals[MAX_WORKERS] = {};

    std::mutex worker_count_mutex;
    size_t current_workers = 0;

    JobBoard& job_board;

    PImpl(JobBoard& job_board_) : job_board(job_board_) {}

    ~PImpl()
    {
      set_task_threads(0);
    }

    PImpl(const PImpl&) = delete;
    PImpl& operator=(const PImpl&) = delete;

    PImpl(PImpl&&) = delete;
    PImpl& operator=(PImpl&&) = delete;

    void set_task_threads(size_t new_worker_count)
    {
      std::unique_lock<std::mutex> lock(worker_count_mutex);

      if (new_worker_count >= MAX_WORKERS)
      {
        throw std::logic_error(fmt::format(
          "Cannot create {} workers. Max permitted is {}",
          new_worker_count,
          MAX_WORKERS));
      }

      if (new_worker_count < current_workers)
      {
        // Stop workers
        // Do this in 2 loops, so that the stop_signals can be processed
        // concurrently
        for (auto i = new_worker_count; i < current_workers; ++i)
        {
          stop_signals[i].value.store(true);
        }

        for (auto i = new_worker_count; i < current_workers; ++i)
        {
          workers[i].join();
        }
      }
      else if (new_worker_count > current_workers)
      {
        // Start workers
        for (auto i = current_workers; i < new_worker_count; ++i)
        {
          auto& stop_signal = stop_signals[i].value;
          stop_signal.store(false);
          workers[i] = std::thread(
            task_worker_loop, std::ref(job_board), std::ref(stop_signal));
        }
      }

      current_workers = new_worker_count;
    }
  };

  ThreadManager::ThreadManager(JobBoard& job_board_) :
    pimpl(std::make_unique<PImpl>(job_board_))
  {}

  ThreadManager::~ThreadManager() = default;

  void ThreadManager::set_task_threads(size_t new_worker_count)
  {
    pimpl->set_task_threads(new_worker_count);
  }
}
