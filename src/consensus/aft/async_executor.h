// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/thread_messaging.h"

namespace aft
{
  enum class AsyncSchedulingResult
  {
    SYNCH_POINT,
    DONE
  };

  enum class AsyncExecutorState
  {
    INITIAL_TX,
    SYNCH_POINT,
    NORMAL
  };

  class AsyncExecutor
  {
  private:
    uint32_t pending_cbs = 0;
    bool run_sync = threading::ThreadMessaging::thread_count == 1;
    AsyncExecutorState state;
    uint64_t execution_start_idx;

  public:
    AsyncExecutor(uint16_t thread_count) :
      pending_cbs(0),
      run_sync(thread_count == 1),
      state(AsyncExecutorState::INITIAL_TX),
      execution_start_idx(0)
    {}

    void increment_pending()
    {
      ++pending_cbs;
    }

    AsyncSchedulingResult decrement_pending()
    {
      --pending_cbs;
      return execution_status();
    }

    AsyncSchedulingResult execution_status()
    {
      if (pending_cbs == 0)
      {
        return AsyncSchedulingResult::DONE;
      }
      return AsyncSchedulingResult::SYNCH_POINT;
    }

    void execute_as_far_as_possible(kv::Version max_tx_idx_in_block)
    {
      state = AsyncExecutorState::INITIAL_TX;
      execution_start_idx = max_tx_idx_in_block;
    }

    bool should_exec_next_append_entry(
      bool support_async_execution, uint64_t max_conflict_version)
    {
      if (run_sync)
      {
        return true;
      }

      if (state==AsyncExecutorState::SYNCH_POINT)
      {
        return false;
      }

      if (execution_status() == AsyncSchedulingResult::SYNCH_POINT)
      {
        if (!support_async_execution && state != AsyncExecutorState::INITIAL_TX)
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

      if (
     !support_async_execution &&
        (execution_status() == AsyncSchedulingResult::SYNCH_POINT))
      {
        state = AsyncExecutorState::SYNCH_POINT;
      }
      else
      {
        state = AsyncExecutorState::NORMAL;
      }

      return true;
    }
  };
}