// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/locking.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <iostream>
#include <memory>

namespace ccf::ds
{
  class WorkBeacon
  {
  protected:
    ccf::ds::Mutex mutex;
    ccf::ds::ConditionVariable condition_variable;
    size_t work_available CCF_GUARDED_BY(mutex) = 0;

  public:
    void wait_for_work()
    {
      ccf::ds::MutexGuard lock(mutex);
      condition_variable.wait(
        lock, [this]() CCF_REQUIRES(mutex) { return work_available > 0; });
      --work_available;
    }

    // Returns true if condition variable indicated work is available, false if
    // timeout was reached
    template <typename DurationRep, typename DurationPeriod>
    bool wait_for_work_with_timeout(
      const std::chrono::duration<DurationRep, DurationPeriod>& timeout)
    {
      ccf::ds::MutexGuard lock(mutex);
      const auto woke_for_work = condition_variable.wait_for(
        lock, timeout, [this]() CCF_REQUIRES(mutex) {
          return work_available > 0;
        });
      if (woke_for_work)
      {
        --work_available;
      }

      return woke_for_work;
    }

    void notify_work_available()
    {
      {
        ccf::ds::MutexGuard lock(mutex);
        ++work_available;
      }

      condition_variable.notify_all();
    }
  };

  using WorkBeaconPtr = std::shared_ptr<WorkBeacon>;
}
