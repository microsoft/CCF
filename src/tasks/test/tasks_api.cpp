// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <doctest/doctest.h>
#include <iostream>
#include <numeric>

// Other tests flush local JobBoards. This tests the static API of
// task_system.h, that real code will use

TEST_CASE("API" * doctest::test_suite("tasks_api"))
{
  ccf::tasks::set_worker_count(0);

  {
    INFO("Single task");
    std::atomic<bool> a = false;
    ccf::tasks::Task toggle_a =
      ccf::tasks::make_basic_task([&a]() { a.store(true); });
    ccf::tasks::add_task(toggle_a);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE_FALSE(a.load());

    ccf::tasks::set_worker_count(1);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE(a.load());

    ccf::tasks::set_worker_count(0);
  }

  {
    INFO("Periodic task");
    std::atomic<size_t> n = 0;
    auto prev = n.load();
    ccf::tasks::Task incrementer = ccf::tasks::make_basic_task([&n]() { ++n; });

    ccf::tasks::add_periodic_task(
      incrementer,
      std::chrono::milliseconds(0),
      std::chrono::milliseconds(100));
    ccf::tasks::add_periodic_task(
      incrementer,
      std::chrono::milliseconds(20),
      std::chrono::milliseconds(33));

    ccf::tasks::set_worker_count(4);

    const std::chrono::milliseconds delay(1);

    for (auto i = 0; i < 1000; ++i)
    {
      ccf::tasks::tick(delay);
      std::this_thread::sleep_for(delay);

      if (i % 100 == 0)
      {
        auto now = n.load();
        REQUIRE(now > prev);
        prev = now;
      }
    }

    incrementer->cancel_task();

    ccf::tasks::set_worker_count(0);
  }
}