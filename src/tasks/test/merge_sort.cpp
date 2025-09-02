// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/ordered_tasks.h"
#include "tasks/task_system.h"

#define FMT_HEADER_ONLY
#include <doctest/doctest.h>
#include <fmt/chrono.h>
#include <fmt/format.h>

struct MergeSortTask : public ccf::tasks::BaseTask,
                       public std::enable_shared_from_this<MergeSortTask>
{
  using Iterator = std::vector<int>::iterator;

  Iterator begin;
  Iterator end;
  std::shared_ptr<MergeSortTask> parent;
  std::atomic<size_t> sub_tasks;

  MergeSortTask(
    Iterator b, Iterator e, std::shared_ptr<MergeSortTask> p = nullptr) :
    begin(b),
    end(e),
    parent(p)
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
  }

  void do_task_implementation() override
  {
    const auto dist = std::distance(begin, end);
    if (dist >= 100)
    {
      sub_tasks.store(2);

      auto self = shared_from_this();

      auto mid_point = begin + (dist / 2);

      ccf::tasks::add_task(
        std::make_shared<MergeSortTask>(begin, mid_point, self));
      ccf::tasks::add_task(
        std::make_shared<MergeSortTask>(mid_point, end, self));
    }
    else
    {
      merge();
    }
  }
};

void loop_until_empty(
  size_t worker_count,
  std::chrono::seconds kill_after = std::chrono::seconds(5))
{
  std::atomic<bool> stop_signal{false};

  std::vector<std::thread> workers;
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&stop_signal]() {
      while (!stop_signal.load())
      {
        auto task = ccf::tasks::get_main_job_board().get_task();
        if (task != nullptr)
        {
          task->do_task();
        }
        std::this_thread::yield();
      }
    });
  }

  using TClock = std::chrono::steady_clock;
  auto now = TClock::now();

  const auto hard_end = now + kill_after;

  while (true)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    now = TClock::now();
    if (now > hard_end)
    {
      break;
    }

    if (ccf::tasks::get_main_job_board().empty())
    {
      break;
    }
  }

  stop_signal.store(true);

  for (auto& _worker : workers)
  {
    _worker.join();
  }
}

std::chrono::milliseconds do_merge_sort(size_t worker_count, size_t data_size)
{
  std::vector<int> ns;
  for (size_t i = 0; i < data_size; ++i)
  {
    ns.emplace_back(rand());
  }
  REQUIRE_FALSE(std::is_sorted(ns.begin(), ns.end()));

  ccf::tasks::add_task(std::make_shared<MergeSortTask>(ns.begin(), ns.end()));

  auto start = std::chrono::high_resolution_clock::now();
  loop_until_empty(worker_count);
  auto end = std::chrono::high_resolution_clock::now();

  REQUIRE(ccf::tasks::get_main_job_board().empty());
  REQUIRE(std::is_sorted(ns.begin(), ns.end()));

  return std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
}

TEST_CASE("MergeSort")
{
  for (auto size : {
         1'000'000,
         2'000'000,
         4'000'000,
       })
  {
    for (auto n : {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
    {
      const auto duration = do_merge_sort(n, size);
      std::cout << fmt::format(
        std::locale("en_US.UTF-8"),
        "{:>2} workers took {:>8L} to merge_sort {:11L} elements\n",
        n,
        duration,
        size);
    }
  }
}
