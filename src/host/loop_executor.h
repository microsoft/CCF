// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"

#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace asynchost
{
  // A thread-safe queue of work items to be executed on the libuv loop thread.
  //
  // Any thread may enqueue work via enqueue(); the work is run later, on the
  // loop thread, when flush() is called (typically driven by a libuv Timer via
  // on_timer()). This mirrors the existing host pattern of draining the
  // enclave->host ringbuffer on a periodic Timer, and provides a safe way to
  // marshal operations that must run on the loop thread (e.g. libuv socket
  // operations, which are not thread-safe) when they are requested from other
  // threads (e.g. the enclave worker threads).
  class LoopExecutorImpl
  {
  public:
    using Work = std::function<void()>;

  private:
    ccf::pal::Mutex lock;
    std::vector<Work> pending;

  public:
    // May be called from any thread.
    void enqueue(Work work)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      pending.emplace_back(std::move(work));
    }

    // Must be called on the loop thread. Runs all work that was queued at the
    // point of the call, in the order it was enqueued. Work enqueued while
    // flushing (including by the work items themselves) is left for a
    // subsequent flush, so this never loops indefinitely.
    void flush()
    {
      std::vector<Work> to_run;
      {
        std::lock_guard<ccf::pal::Mutex> guard(lock);
        std::swap(to_run, pending);
      }

      for (auto& work : to_run)
      {
        work();
      }
    }

    // Called by the driving Timer on the loop thread.
    void on_timer()
    {
      flush();
    }
  };

  // Timer behaviour that drains a LoopExecutorImpl on the loop thread. Drive
  // this with an asynchost::Timer at a small interval, e.g.
  //   proxy_ptr<Timer<LoopExecutorDrainer>> t(1ms, executor);
  struct LoopExecutorDrainer
  {
    std::shared_ptr<LoopExecutorImpl> executor;

    explicit LoopExecutorDrainer(std::shared_ptr<LoopExecutorImpl> executor_) :
      executor(std::move(executor_))
    {}

    void on_timer()
    {
      executor->flush();
    }
  };
}
