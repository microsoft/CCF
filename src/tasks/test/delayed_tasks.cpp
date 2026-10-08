// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "tasks/basic_task.h"
#include "tasks/periodic_task_owner.h"
#include "tasks/task_system.h"

#include <doctest/doctest.h>
#include <future>
#include <latch>
#include <thread>

namespace
{
  // Exposes protected scheduling so tests can exercise owner lifetime and
  // independent callbacks without implementing a production component.
  class TestPeriodicTaskOwner : public ccf::tasks::PeriodicTaskOwner
  {
  public:
    using PeriodicTaskOwner::schedule_periodic_task;
  };

  struct FakeTime
  {
    ccf::tasks::JobBoard& job_board;

    const std::chrono::milliseconds polling_period{1};

    void sleep_for(size_t workers, std::chrono::milliseconds duration)
    {
      std::chrono::milliseconds elapsed{0};

      while (elapsed < duration)
      {
        job_board.tick(polling_period);

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

  class BlockingPeriodicTaskOwner : public ccf::tasks::PeriodicTaskOwner
  {
  public:
    std::latch first_execution_started{1};
    std::latch release_first_execution{1};
    std::vector<std::chrono::milliseconds> elapsed;

    void start(
      ccf::tasks::JobBoard& job_board, std::chrono::milliseconds period)
    {
      schedule_periodic_task(
        job_board,
        period,
        [this](std::chrono::milliseconds elapsed_) {
          const auto is_first = elapsed.empty();
          elapsed.push_back(elapsed_);
          if (is_first)
          {
            first_execution_started.count_down();
            release_first_execution.wait();
          }
        },
        "Blocking periodic task");
    }
  };
}

TEST_CASE("DelayedTasks" * doctest::test_suite("delayed_tasks"))
{
  ccf::tasks::JobBoard job_board;

  FakeTime fake_time{job_board};

  std::atomic<size_t> n = 0;
  ccf::tasks::Task incrementer =
    ccf::tasks::make_basic_task([&n]() { ++n; }, "incrementer");

  job_board.add_task(incrementer);
  // Task is not done when no workers are present
  REQUIRE(n.load() == 0);

  {
    fake_time.sleep_for(1, fake_time.polling_period * 2);
    REQUIRE(n.load() == 1);
  }

  std::chrono::milliseconds delay = std::chrono::milliseconds(50);
  job_board.add_delayed_task(incrementer, delay);
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

  job_board.add_periodic_task(incrementer, delay, delay);
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

void do_all_tasks(ccf::tasks::JobBoard& job_board)
{
  auto task = job_board.get_task();
  while (task != nullptr)
  {
    task->do_task();
    task = job_board.get_task();
  }
}

TEST_CASE("ExplicitTicks" * doctest::test_suite("delayed_tasks"))
{
  ccf::tasks::JobBoard job_board;

  std::atomic<bool> a = false;
  std::atomic<bool> b = false;
  std::atomic<bool> c = false;

  auto set_a = ccf::tasks::make_basic_task([&a]() { a.store(true); });
  auto set_b = ccf::tasks::make_basic_task([&b]() { b.store(true); });
  auto set_c = ccf::tasks::make_basic_task([&c]() { c.store(true); });

  using namespace std::chrono_literals;
  job_board.add_periodic_task(set_a, 5ms, 5ms);
  job_board.add_periodic_task(set_b, 7ms, 8ms);
  job_board.add_delayed_task(set_c, 20ms);
  auto do_all_check_and_reset = [&job_board, &a, &b, &c](
                                  std::string_view label,
                                  bool expected_a,
                                  bool expected_b,
                                  bool expected_c) {
    DOCTEST_INFO(label);
    do_all_tasks(job_board);

    REQUIRE(a == expected_a);
    REQUIRE(b == expected_b);
    REQUIRE(c == expected_c);

    a.store(false);
    b.store(false);
    c.store(false);
  };

  do_all_check_and_reset("0ms", false, false, false);

  job_board.tick(1ms);
  do_all_check_and_reset("1ms", false, false, false);

  job_board.tick(3ms);
  do_all_check_and_reset("4ms", false, false, false);

  job_board.tick(1ms);
  // First set_a is enqueued, but not yet run
  REQUIRE(a == false);
  do_all_check_and_reset("5ms", true, false, false); // First set_a
  do_all_check_and_reset("5ms (after reset)", false, false, false);

  job_board.tick(1ms);
  do_all_check_and_reset("6ms", false, false, false);

  job_board.tick(1ms);
  do_all_check_and_reset("7ms", false, true, false); // First set_b

  job_board.tick(2ms);
  do_all_check_and_reset("9ms", false, false, false);

  job_board.tick(1ms);
  do_all_check_and_reset("10ms", true, false, false); // Second set_a

  job_board.tick(4ms);
  do_all_check_and_reset("14ms", false, false, false); // Second set_a

  job_board.tick(1ms);
  do_all_check_and_reset("15ms", true, true, false); // set_a and set_b

  job_board.tick(4ms);
  do_all_check_and_reset("19ms", false, false, false);

  job_board.tick(1ms);
  do_all_check_and_reset("20ms", true, false, true); // set_a and set_c

  job_board.tick(6ms);
  do_all_check_and_reset("26ms", true, true, false); // set_a@25, set_b@23

  // Repeats do not correct for large ticks, they just add the repeat value to
  // the current elapsed.
  // Next set_a is now at 26 + 5 = 31 (NOT 25 + 5 = 30)
  // Next set_b is now at 26 + 8 = 34 (NOT 23 + 8 = 31)

  job_board.tick(4ms);
  do_all_check_and_reset("30ms", false, false, false);

  job_board.tick(1ms);
  do_all_check_and_reset("31ms", true, false, false);

  job_board.tick(3ms);
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

  ccf::tasks::JobBoard job_board;

  std::atomic<size_t> n = 0;

  auto incrementer = ccf::tasks::make_basic_task([&n]() { ++n; });

  using namespace std::chrono_literals;
  job_board.add_periodic_task(incrementer, 1ms, 1ms);

  REQUIRE(n.load() == 0);
  job_board.tick(100ms);
  do_all_tasks(job_board);
  REQUIRE(n.load() == 1);
  do_all_tasks(job_board);
  REQUIRE(n.load() == 1);

  incrementer->cancel_task();
}

TEST_CASE(
  "Independent periodic tasks share an owner, not an execution lock" *
  doctest::test_suite("delayed_tasks"))
{
  using namespace std::chrono_literals;
  ccf::tasks::JobBoard job_board;
  auto owner = std::make_shared<TestPeriodicTaskOwner>();
  std::promise<void> first_started;
  auto first_started_future = first_started.get_future();
  std::latch release_first{1};
  std::vector<std::chrono::milliseconds> first_elapsed, second_elapsed;
  owner->schedule_periodic_task(
    job_board,
    10ms,
    [&](auto elapsed) {
      const auto is_first = first_elapsed.empty();
      first_elapsed.push_back(elapsed);
      if (is_first)
      {
        first_started.set_value();
        release_first.wait();
      }
    },
    "Blocking callback");
  owner->schedule_periodic_task(
    job_board,
    10ms,
    [&](auto elapsed) { second_elapsed.push_back(elapsed); },
    "Independent callback");

  job_board.tick(10ms);
  auto first = job_board.get_task();
  REQUIRE(first != nullptr);
  std::thread worker([&]() { first->do_task(); });
  const auto first_did_start =
    first_started_future.wait_for(5s) == std::future_status::ready;
  std::promise<void> independent_finished;
  auto independent_future = independent_finished.get_future();
  std::thread independent_worker([&]() {
    do_all_tasks(job_board);
    job_board.tick(35ms);
    do_all_tasks(job_board);
    independent_finished.set_value();
  });
  // A blocking-lock regression must still reach release/join before failure.
  const auto independent_completed =
    independent_future.wait_for(5s) == std::future_status::ready;
  std::weak_ptr<TestPeriodicTaskOwner> weak_owner = owner;
  owner.reset();
  const auto retained_while_running = !weak_owner.expired();
  release_first.count_down();
  worker.join();
  independent_worker.join();

  REQUIRE(first_did_start);
  REQUIRE(independent_completed);
  REQUIRE(first_elapsed == std::vector{10ms});
  REQUIRE(second_elapsed == std::vector{10ms, 35ms});
  REQUIRE(retained_while_running);
  REQUIRE(weak_owner.expired());
  job_board.tick(100ms);
  do_all_tasks(job_board);
  REQUIRE(first_elapsed.size() == 1);
  REQUIRE(second_elapsed.size() == 2);
}

TEST_CASE(
  "Periodic task owner destruction and board shutdown" *
  doctest::test_suite("delayed_tasks"))
{
  using namespace std::chrono_literals;
  ccf::tasks::JobBoard job_board;
  auto owner = std::make_shared<TestPeriodicTaskOwner>();
  size_t calls = 0;
  owner->schedule_periodic_task(
    job_board, 10ms, [&](auto) { ++calls; }, "Tick");
  job_board.tick(10ms);
  REQUIRE(job_board.get_summary().pending_tasks == 1);

  SUBCASE("Destruction leaves no owned callback on the board")
  {
    std::weak_ptr<TestPeriodicTaskOwner> weak_owner = owner;
    owner.reset();
    REQUIRE(weak_owner.expired());
  }
  SUBCASE("Board shutdown discards periodic work")
  {
    job_board.shutdown();
  }

  do_all_tasks(job_board);
  job_board.tick(100ms);
  do_all_tasks(job_board);
  REQUIRE(calls == 0);
}

TEST_CASE(
  "PeriodicTaskOwner coalesces overlap" * doctest::test_suite("delayed_tasks"))
{
  using namespace std::chrono_literals;

  ccf::tasks::JobBoard job_board;
  auto owner = std::make_shared<BlockingPeriodicTaskOwner>();
  owner->start(job_board, 1ms);

  job_board.tick(1ms);
  auto first = job_board.get_task();
  REQUIRE(first != nullptr);
  std::thread first_worker([first]() { first->do_task(); });
  owner->first_execution_started.wait();

  job_board.tick(1ms);
  auto overlapping = job_board.get_task();
  REQUIRE(overlapping != nullptr);
  std::atomic<bool> overlapping_finished = false;
  std::thread second_worker([&]() {
    overlapping->do_task();
    overlapping_finished.store(true);
  });

  std::this_thread::sleep_for(10ms);
  const auto overlap_was_coalesced = overlapping_finished.load();
  owner->release_first_execution.count_down();
  first_worker.join();
  second_worker.join();
  REQUIRE(overlap_was_coalesced);

  job_board.tick(1ms);
  auto next = job_board.get_task();
  REQUIRE(next != nullptr);
  next->do_task();
  REQUIRE(owner->elapsed == std::vector{1ms, 2ms});
}
