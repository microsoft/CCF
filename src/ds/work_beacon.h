// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>

namespace ccf::ds
{
  class WorkBeacon
  {
  protected:
    std::mutex mutex;
    std::condition_variable condition_variable;
    bool work_available;

  public:
    void wait_for_work()
    {
      std::unique_lock<std::mutex> lock(mutex);
      condition_variable.wait(lock, [this] { return work_available; });
      work_available = false;
    }

    void notify_work_available()
    {
      {
        std::lock_guard<std::mutex> lock(mutex);
        work_available = true;
      }

      condition_variable.notify_all();
    }
  };

  using WorkBeaconPtr = std::shared_ptr<WorkBeacon>;
}
