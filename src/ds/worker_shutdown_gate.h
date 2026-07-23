// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>

namespace ccf::ds
{
  /**
   * A cooperative shutdown gate for worker threads.
   *
   * Workers call try_register() before accessing a shared resource and
   * unregister() when done. The owner calls shutdown_and_wait() to reject new
   * registrations and block until all active workers have finished.
   *
   * This is shared via std::shared_ptr so that queued-but-not-yet-started
   * workers can inspect it without accessing the destroyed owner.
   */
  class WorkerShutdownGate
  {
  private:
    std::mutex lock;
    std::condition_variable all_workers_done;
    size_t active_workers = 0;
    bool alive = true;

  public:
    /**
     * Attempt to register a worker. Returns true if registration succeeded
     * (the gate is still open). Returns false if shutdown has begun - the
     * caller must not proceed to access the protected resource.
     */
    [[nodiscard]] bool try_register()
    {
      std::unique_lock<std::mutex> guard(lock);
      if (!alive)
      {
        return false;
      }
      ++active_workers;
      return true;
    }

    /**
     * Unregister a previously registered worker. Wakes the shutdown waiter
     * if this was the last active worker.
     */
    void unregister()
    {
      std::unique_lock<std::mutex> guard(lock);
      --active_workers;
      if (active_workers == 0)
      {
        all_workers_done.notify_all();
      }
    }

    /**
     * Signal shutdown and block until all registered workers have called
     * unregister(). After this returns, try_register() will always return
     * false. Must be called at most once.
     */
    void shutdown_and_wait()
    {
      std::unique_lock<std::mutex> guard(lock);
      alive = false;
      all_workers_done.wait(guard, [this]() { return active_workers == 0; });
    }

    /**
     * Non-blocking check for whether shutdown has been initiated.
     */
    [[nodiscard]] bool is_shutting_down() const
    {
      // alive is only ever written under the lock and only transitions
      // false->true, so a relaxed read is safe for a non-blocking check.
      // However, to avoid UB we still take the lock briefly.
      auto* self = const_cast<WorkerShutdownGate*>(this);
      std::unique_lock<std::mutex> guard(self->lock);
      return !alive;
    }

    /**
     * RAII guard that calls unregister() on destruction. Intended to be used
     * after a successful try_register() to ensure unregister() is called on
     * every exit path.
     */
    struct UnregisterGuard
    {
      std::shared_ptr<WorkerShutdownGate> gate;
      ~UnregisterGuard()
      {
        gate->unregister();
      }
    };
  };
}
