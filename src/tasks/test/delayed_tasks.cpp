// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <doctest/doctest.h>

namespace
{
  struct FakeTime
  {
    const std::chrono::milliseconds polling_period{1};

    void sleep_for(size_t workers, std::chrono::milliseconds duration)
    {
      std::chrono::milliseconds elapsed{0};

      auto& job_board = ccf::tasks::get_main_job_board();

      while (elapsed < duration)
      {
        ccf::tasks::tick(polling_period);

        size_t worker_idx = 0;
        while (worker_idx < workers)
        {
          auto task = job_board.get_task();
          if (task != nullptr)
          {
            task->do_task();
            ++worker_idx;
          }
          else
          {
            break;
          }
        }

        elapsed += polling_period;
      }
    }
  };
}

TEST_CASE("DelayedTasks" * doctest::test_suite("delayed_tasks"))
{
  FakeTime fake_time;

  std::atomic<size_t> n = 0;
  ccf::tasks::Task incrementer =
    ccf::tasks::make_basic_task([&n]() { ++n; }, "incrementer");

  ccf::tasks::add_task(incrementer);
  // Task is not done when no workers are present
  REQUIRE(n.load() == 0);

  {
    fake_time.sleep_for(1, fake_time.polling_period * 2);
    REQUIRE(n.load() == 1);
  }

  std::chrono::milliseconds delay = std::chrono::milliseconds(50);
  ccf::tasks::add_delayed_task(incrementer, delay);
  // Delayed task is not done when no workers are present
  REQUIRE(n.load() == 1);
  // Even after waiting for delay
  fake_time.sleep_for(0, delay * 2);
  REQUIRE(n.load() == 1);

  {
    // Delayed task is executed when worker thread arrives
    fake_time.sleep_for(1, delay * 2);
    REQUIRE(n.load() == 2);
    // Task is only executed once
    fake_time.sleep_for(1, delay * 2);
    REQUIRE(n.load() == 2);
  }

  ccf::tasks::add_periodic_task(incrementer, delay, delay);
  // Periodic task is not done when no workers are present
  REQUIRE(n.load() == 2);
  // Even after waiting for delay
  fake_time.sleep_for(0, delay * 2);
  REQUIRE(n.load() == 2);

  {
    // Periodic task is executed when worker thread arrives
    fake_time.sleep_for(1, delay * 2);
    const auto a = n.load();
    REQUIRE(a > 2);

    // Periodic task is executed multiple times
    fake_time.sleep_for(1, delay * 2);
    const auto b = n.load();
    REQUIRE(b > a);

    // Periodic task is cancellable
    incrementer->cancel_task();

    fake_time.sleep_for(1, delay * 2);
    const auto c = n.load();
    REQUIRE(c >= b);

    fake_time.sleep_for(1, delay * 2);
    const auto d = n.load();
    REQUIRE(d == c);
  }
}

void do_all_tasks()
{
  auto& job_board = ccf::tasks::get_main_job_board();
  auto task = job_board.get_task();
  while (task != nullptr)
  {
    task->do_task();
    task = job_board.get_task();
  }
}

TEST_CASE("ExplicitTicks" * doctest::test_suite("delayed_tasks"))
{
  std::atomic<bool> a = false;
  std::atomic<bool> b = false;
  std::atomic<bool> c = false;

  auto set_a = ccf::tasks::make_basic_task([&a]() { a.store(true); });
  auto set_b = ccf::tasks::make_basic_task([&b]() { b.store(true); });
  auto set_c = ccf::tasks::make_basic_task([&c]() { c.store(true); });

  using namespace std::chrono_literals;
  ccf::tasks::add_periodic_task(set_a, 5ms, 5ms);
  ccf::tasks::add_periodic_task(set_b, 7ms, 8ms);
  ccf::tasks::add_delayed_task(set_c, 20ms);
  auto do_all_check_and_reset = [&a, &b, &c](
                                  std::string_view label,
                                  bool expected_a,
                                  bool expected_b,
                                  bool expected_c) {
    DOCTEST_INFO(label);
    do_all_tasks();

    REQUIRE(a == expected_a);
    REQUIRE(b == expected_b);
    REQUIRE(c == expected_c);

    a.store(false);
    b.store(false);
    c.store(false);
  };

  do_all_check_and_reset("0ms", false, false, false);

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("1ms", false, false, false);

  ccf::tasks::tick(3ms);
  do_all_check_and_reset("4ms", false, false, false);

  ccf::tasks::tick(1ms);
  // First set_a is enqueued, but not yet run
  REQUIRE(a == false);
  do_all_check_and_reset("5ms", true, false, false); // First set_a
  do_all_check_and_reset("5ms (after reset)", false, false, false);

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("6ms", false, false, false);

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("7ms", false, true, false); // First set_b

  ccf::tasks::tick(2ms);
  do_all_check_and_reset("9ms", false, false, false);

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("10ms", true, false, false); // Second set_a

  ccf::tasks::tick(4ms);
  do_all_check_and_reset("14ms", false, false, false); // Second set_a

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("15ms", true, true, false); // set_a and set_b

  ccf::tasks::tick(4ms);
  do_all_check_and_reset("19ms", false, false, false);

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("20ms", true, false, true); // set_a and set_c

  ccf::tasks::tick(6ms);
  do_all_check_and_reset("26ms", true, true, false); // set_a@25, set_b@23

  // Repeats do not correct for large ticks, they just add the repeat value to
  // the current elapsed.
  // Next set_a is now at 26 + 5 = 31 (NOT 25 + 5 = 30)
  // Next set_b is now at 26 + 8 = 34 (NOT 23 + 8 = 31)

  ccf::tasks::tick(4ms);
  do_all_check_and_reset("30ms", false, false, false);

  ccf::tasks::tick(1ms);
  do_all_check_and_reset("31ms", true, false, false);

  ccf::tasks::tick(3ms);
  do_all_check_and_reset("34ms", false, true, false);

  set_a->cancel_task();
  set_b->cancel_task();
  set_c->cancel_task();
}

TEST_CASE("TickEnqueue" * doctest::test_suite("delayed_tasks"))
{
  INFO(
    "Each tick will only trigger a single instance of a task, even if multiple "
    "periods have elapsed");

  std::atomic<size_t> n = 0;

  auto incrementer = ccf::tasks::make_basic_task([&n]() { ++n; });

  using namespace std::chrono_literals;
  ccf::tasks::add_periodic_task(incrementer, 1ms, 1ms);

  REQUIRE(n.load() == 0);
  ccf::tasks::tick(100ms);
  do_all_tasks();
  REQUIRE(n.load() == 1);
  do_all_tasks();
  REQUIRE(n.load() == 1);

  incrementer->cancel_task();
}
