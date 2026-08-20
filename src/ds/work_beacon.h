// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <iostream>
#include <memory>

namespace ccf::ds
{
  class WorkBeacon
  {
  protected:
    ccf::pal::Mutex mutex;
    ccf::pal::ConditionVariable condition_variable;
    size_t work_available CCF_GUARDED_BY(mutex) = 0;

  public:
    void wait_for_work()
    {
      ccf::pal::MutexGuard lock(mutex);
      while (work_available == 0)
      {
        condition_variable.wait(lock);
      }
      --work_available;
    }

    // Returns true if condition variable indicated work is available, false if
    // timeout was reached
    template <typename DurationRep, typename DurationPeriod>
    bool wait_for_work_with_timeout(
      const std::chrono::duration<DurationRep, DurationPeriod>& timeout)
    {
      ccf::pal::MutexGuard lock(mutex);
      const auto deadline = std::chrono::steady_clock::now() + timeout;
      while (work_available == 0)
      {
        const auto status = condition_variable.wait_until(lock, deadline);
        if (status == std::cv_status::timeout && work_available == 0)
        {
          return false;
        }
      }

      --work_available;
      return true;
    }

    void notify_work_available()
    {
      {
        ccf::pal::MutexGuard lock(mutex);
        ++work_available;
      }

      condition_variable.notify_all();
    }
  };

  using WorkBeaconPtr = std::shared_ptr<WorkBeacon>;
}
