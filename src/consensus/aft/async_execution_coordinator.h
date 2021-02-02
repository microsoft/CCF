// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/thread_messaging.h"

namespace aft
{
  enum class AsyncExecutionResult
  {
    PENDING,
    COMPLETE
  };

  class AsyncExecutor
  {
  private:
    uint32_t pending_cbs = 0;
    bool run_sync = threading::ThreadMessaging::thread_count == 1;
    bool is_first;
    bool must_break;
    uint64_t execution_start_idx;

  public:
    AsyncExecutor(uint16_t thread_count) :
      pending_cbs(0),
      run_sync(thread_count == 1)
    {}

    void increment_pending()
    {
      ++pending_cbs;
    }

    AsyncExecutionResult decrement_pending()
    {
      --pending_cbs;
      return execution_status();
    }

    AsyncExecutionResult execution_status()
    {
      if (pending_cbs == 0)
      {
        return AsyncExecutionResult::COMPLETE;
      }
      return AsyncExecutionResult::PENDING;
    }

    void execute_as_far_as_possible(kv::Version start_idx)
    {
      is_first = true;
      must_break = false;
      execution_start_idx = start_idx;
    }

    bool should_exec_next_append_entry(
      bool support_async_execution, uint64_t max_conflict_version)
    {
      if (!run_sync)
      {
        if (must_break)
        {
          return false;
        }

        if (execution_status() == AsyncExecutionResult::PENDING)
        {
          if (!support_async_execution && !is_first)
          {
            return false;
          }

          if (
            support_async_execution &&
            max_conflict_version >= execution_start_idx)
          {
            return false;
          }
        }
      }

      is_first = false;
      must_break = !support_async_execution &&
        (execution_status() == AsyncExecutionResult::PENDING);

      return true;
    }
  };
}