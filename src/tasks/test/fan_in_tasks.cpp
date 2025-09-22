// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/fan_in_tasks.h"

#include "./utils.h"
#include "tasks/basic_task.h"
#include "tasks/job_board.h"

#include <doctest/doctest.h>
#include <thread>

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>

TEST_CASE("ContiguousQueuing" * doctest::test_suite("fan_in_tasks"))
{
  ccf::tasks::JobBoard jb;
  ccf::tasks::Task task;

  auto collection = ccf::tasks::FanInTasks::create(jb);

  REQUIRE(jb.empty());

  std::atomic<bool> done_0{false};
  std::atomic<bool> done_1{false};
  std::atomic<bool> done_2{false};

  auto set_0 = ccf::tasks::make_basic_task([&]() { done_0.store(true); });
  auto set_1 = ccf::tasks::make_basic_task([&]() { done_1.store(true); });
  auto set_2 = ccf::tasks::make_basic_task([&]() { done_2.store(true); });

  // Adding the next-contiguous task instantly enqueues this collection
  collection->add_task(0, set_0);
  REQUIRE_FALSE(jb.empty());

  // Non-contiguous tasks can be stored
  collection->add_task(2, set_2);

  task = jb.get_task();
  REQUIRE(task != nullptr);

  // Only a contiguous block is executed
  REQUIRE_FALSE(done_0.load());
  REQUIRE_FALSE(done_2.load());
  task->do_task();
  REQUIRE(done_0.load());
  REQUIRE_FALSE(done_2.load());

  // Enqueuing invalid indices results in an error
  auto never_execd = ccf::tasks::make_basic_task([]() { REQUIRE(false); });
  REQUIRE_THROWS(collection->add_task(0, never_execd));
  REQUIRE_THROWS(collection->add_task(2, never_execd));

  // Contiguous next task may arrive out-of-order, queuing a batch of tasks
  REQUIRE(jb.empty());
  collection->add_task(1, set_1);
  REQUIRE_FALSE(jb.empty());

  task = jb.get_task();
  REQUIRE(task != nullptr);

  REQUIRE_FALSE(done_1.load());
  REQUIRE_FALSE(done_2.load());
  task->do_task();
  REQUIRE(done_1.load());
  REQUIRE(done_2.load());
}

TEST_CASE("InterleavedCompletions" * doctest::test_suite("fan_in_tasks"))
{
  // Testing mutexes + re-enqueuing logic of FanInTasks, where tasks are added
  // to the collection _while the collection is being executed_
  ccf::tasks::JobBoard jb;
  ccf::tasks::Task task;

  auto collection = ccf::tasks::FanInTasks::create(jb);

  std::atomic<bool> all_done{false};
  collection->add_task(
    0, ccf::tasks::make_basic_task([&]() {
      collection->add_task(
        1, ccf::tasks::make_basic_task([&]() { all_done.store(true); }));
    }));

  REQUIRE_FALSE(jb.empty());
  task = jb.get_task();
  REQUIRE(task != nullptr);

  REQUIRE_FALSE(all_done.load());
  task->do_task();
  // setter task was _enqueued_, but not _executed_ yet
  REQUIRE_FALSE(all_done.load());

  REQUIRE_FALSE(jb.empty());
  task = jb.get_task();
  REQUIRE(task != nullptr);
  task->do_task();
  REQUIRE(all_done.load());
  REQUIRE(jb.empty());

  {
    // Reset, and try a more complex example
    all_done.store(false);

    collection->add_task(
      2, ccf::tasks::make_basic_task([&]() {
        collection->add_task(
          5, ccf::tasks::make_basic_task([&]() { all_done.store(true); }));
      }));

    REQUIRE_FALSE(jb.empty());
    task = jb.get_task();
    REQUIRE(task != nullptr);
    task->do_task();
    REQUIRE_FALSE(all_done.load());

    collection->add_task(
      3, ccf::tasks::make_basic_task([&]() {
        collection->add_task(
          4, ccf::tasks::make_basic_task([&]() { all_done.store(true); }));
      }));

    REQUIRE_FALSE(jb.empty());
    task = jb.get_task();
    REQUIRE(task != nullptr);
    task->do_task();
    REQUIRE_FALSE(all_done.load());

    REQUIRE_FALSE(jb.empty());
    task = jb.get_task();
    REQUIRE(task != nullptr);
    task->do_task();
    REQUIRE(all_done.load());
    REQUIRE(jb.empty());
  }
}

TEST_CASE("DelayedCompletions" * doctest::test_suite("fan_in_tasks"))
{
  ccf::tasks::JobBoard jb;

  static constexpr size_t num_tasks = 100;

  struct CalledInOrder : public ccf::tasks::BaseTask
  {
    std::atomic<size_t>& counter;
    const size_t expected_value;
    const std::string name;

    CalledInOrder(std::atomic<size_t>& c, size_t ev) :
      counter(c),
      expected_value(ev),
      name(fmt::format("CalledInOrder {}", expected_value))
    {}

    void do_task_implementation() override
    {
      REQUIRE(counter.load() == expected_value);
      ++counter;
    }

    const std::string& get_name() const override
    {
      return name;
    }
  };

  auto completions = ccf::tasks::FanInTasks::create(jb);
  std::atomic<size_t> counter;

  for (auto i = 0; i < num_tasks; ++i)
  {
    jb.add_task(ccf::tasks::make_basic_task([&, i]() {
      const std::chrono::milliseconds sleep_time(rand() % 100);
      std::this_thread::sleep_for(sleep_time);

      completions->add_task(i, std::make_shared<CalledInOrder>(counter, i));
    }));
  }

  test::utils::flush_board(jb, num_tasks);

  // Each task asserted that it executed in-order, and this confirms that all
  // tasks executed
  REQUIRE(counter.load() == num_tasks);
}