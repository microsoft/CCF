// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./task.h"

template <typename BaseT>
struct ICancellableTask : public BaseT
{
  std::atomic<bool> cancelled = false;

  using BaseT::BaseT;

  void cancel_task()
  {
    cancelled.store(true);
  }

  bool is_cancelled()
  {
    return cancelled.load();
  }

  void do_task() override
  {
    if (!cancelled.load())
    {
      BaseT::do_task();
    }
  }
};

template <typename T>
using CancellableTask = std::shared_ptr<ICancellableTask<T>>;

template <typename T, typename... Ts>
CancellableTask<T> make_cancellable_task(Ts&&... ts)
{
  return std::make_shared<ICancellableTask<T>>(std::forward<Ts>(ts)...);
}