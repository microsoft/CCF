// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <condition_variable>
#include <fmt/format.h>
#include <iostream>
#include <memory>
#include <mutex>

namespace ccf::ds
{
  class WorkBeacon
  {
  protected:
    std::mutex mutex;
    std::condition_variable condition_variable;
    size_t work_available = 0;

  public:
    void wait_for_work()
    {
      std::unique_lock<std::mutex> lock(mutex);
      condition_variable.wait(lock, [this] { return work_available > 0; });
      --work_available;
    }

    // Returns true if condition variable indicated work is available, false if
    // timeout was reached
    template <typename DurationRep, typename DurationPeriod>
    bool wait_for_work_with_timeout(
      const std::chrono::duration<DurationRep, DurationPeriod>& timeout)
    {
      std::unique_lock<std::mutex> lock(mutex);
      const auto woke_for_work = condition_variable.wait_for(
        lock, timeout, [this] { return work_available > 0; });
      if (woke_for_work)
      {
        if (work_available > 0)
        {
          --work_available;
        }
      }

      return woke_for_work;
    }

    void notify_work_available()
    {
      {
        std::lock_guard<std::mutex> lock(mutex);
        ++work_available;
      }

      condition_variable.notify_all();
    }
  };

  using WorkBeaconPtr = std::shared_ptr<WorkBeacon>;
}
