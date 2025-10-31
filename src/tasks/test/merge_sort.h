// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task_system.h"

#include <span>

struct MergeSortTask : public ccf::tasks::BaseTask,
                       public std::enable_shared_from_this<MergeSortTask>
{
  // How many items will we actually directly sort, vs forking 2 new tasks to
  // sub-sort
  static constexpr size_t sort_threshold = 50;

  using Iterator = std::span<int>::iterator;

  Iterator begin;
  Iterator end;
  std::atomic<bool>& stop_signal;
  std::shared_ptr<MergeSortTask> parent;
  std::atomic<size_t> sub_tasks;

  MergeSortTask(
    Iterator b,
    Iterator e,
    std::atomic<bool>& ss,
    std::shared_ptr<MergeSortTask> p = nullptr) :
    begin(b),
    end(e),
    parent(p),
    stop_signal(ss)
  {}

  void merge()
  {
    std::sort(begin, end);

    if (parent != nullptr)
    {
      if (--parent->sub_tasks == 0)
      {
        parent->merge();
      }
    }
    else
    {
      stop_signal.store(true);
    }
  }

  void do_task_implementation() override
  {
    const auto dist = std::distance(begin, end);
    if (dist >= sort_threshold)
    {
      sub_tasks.store(2);

      auto self = shared_from_this();

      auto mid_point = begin + (dist / 2);

      ccf::tasks::add_task(
        std::make_shared<MergeSortTask>(begin, mid_point, stop_signal, self));
      ccf::tasks::add_task(
        std::make_shared<MergeSortTask>(mid_point, end, stop_signal, self));
    }
    else
    {
      merge();
    }
  }
};
