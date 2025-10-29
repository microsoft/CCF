// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/ordered_tasks.h"

#include "tasks/basic_task.h"
#include "tasks/sub_task_queue.h"
#include "tasks/thread_manager.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#define FMT_HEADER_ONLY
#include <deque>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <thread>

uint8_t thread_name()
{
  return std::hash<std::thread::id>{}(std::this_thread::get_id());
}

void thread_print(const std::string& s)
{
#if false
  static std::mutex logging_mutex;
  std::lock_guard<std::mutex> guard(logging_mutex);
  fmt::print("[{:0x}] {}\n", thread_name(), s);
#endif
}

// Confirm expected semantics of SubTaskQueue type
TEST_CASE("SubTaskQueue" * doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::SubTaskQueue<size_t> fq;

  // push returns true iff queue was previously empty and inactive
  REQUIRE(fq.push(1));
  REQUIRE_FALSE(fq.push(2));
  REQUIRE_FALSE(fq.push(3));
  REQUIRE_FALSE(fq.push(4));

  // pop returns true iff queue is non-empty when it completes
  REQUIRE_FALSE(fq.pop_and_visit([](size_t&& n) {}));

  // Visits an empty queue, leaves an empty queue
  REQUIRE_FALSE(fq.pop_and_visit([](size_t&& n) {}));

  // Not the first push _ever_, but the first on an empty queue, so gets a true
  // response
  REQUIRE(fq.push(5));

  // If the visitor (or anything concurrent with it) pushes a new element, then
  // the pop returns true to indicate that queue is now non-empty
  REQUIRE(fq.pop_and_visit([&](size_t&& n) {
    // While popping/visiting, the queue is active
    REQUIRE_FALSE(fq.push(6));
  }));

  REQUIRE(fq.pop_and_visit([&](size_t&& n) {
    REQUIRE_FALSE(fq.push(7));
    REQUIRE_FALSE(fq.push(8));
    REQUIRE_FALSE(fq.push(9));
  }));

  REQUIRE_FALSE(fq.pop_and_visit([&](size_t&& n) {}));
}

TEST_CASE("OrderedTasks" * doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::JobBoard job_board;

  auto p_a = ccf::tasks::OrderedTasks::create(job_board);
  auto p_b = ccf::tasks::OrderedTasks::create(job_board);
  auto p_c = ccf::tasks::OrderedTasks::create(job_board);

  std::atomic<bool> executed[14] = {0};

  ccf::tasks::OrderedTasks& tasks_a = *p_a;
  tasks_a.add_action(ccf::tasks::make_basic_action([&]() {
    thread_print("A (no dependencies)");
    executed[0].store(true);
  }));
  tasks_a.add_action(ccf::tasks::make_basic_action([&]() {
    thread_print("B (after A)");
    REQUIRE(executed[0].load());
    executed[1].store(true);
  }));
  tasks_a.add_action(ccf::tasks::make_basic_action([&]() {
    thread_print("C (after B)");
    REQUIRE(executed[1].load());
    executed[2].store(true);
  }));

  ccf::tasks::OrderedTasks& tasks_b = *p_b;
  tasks_b.add_action(ccf::tasks::make_basic_action([&]() {
    thread_print("D (no dependencies)");
    executed[3].store(true);

    tasks_b.add_action(ccf::tasks::make_basic_action([&]() {
      thread_print("E (after D)");
      REQUIRE(executed[3].load());
      executed[4].store(true);

      tasks_b.add_action(ccf::tasks::make_basic_action([&]() {
        thread_print("F (after E)");
        REQUIRE(executed[4].load());
        executed[5].store(true);

        tasks_b.add_action(ccf::tasks::make_basic_action([&]() {
          thread_print("G (after F)");
          REQUIRE(executed[5].load());
          executed[6].store(true);
        }));
      }));
    }));
  }));

  ccf::tasks::OrderedTasks& tasks_c = *p_c;
  tasks_c.add_action(ccf::tasks::make_basic_action([&]() {
    thread_print("I (no dependencies)");
    executed[7].store(true);

    tasks_a.add_action(ccf::tasks::make_basic_action([&]() {
      thread_print("J (after I and C)");
      REQUIRE(executed[2].load());
      REQUIRE(executed[7].load());
      executed[8].store(true);

      tasks_a.add_action(ccf::tasks::make_basic_action([&]() {
        thread_print("K (after J)");
        REQUIRE(executed[8].load());
        executed[9].store(true);

        tasks_c.add_action(ccf::tasks::make_basic_action([&]() {
          thread_print("L (after K)");
          REQUIRE(executed[9].load());
          executed[10].store(true);
        }));
      }));
    }));

    tasks_b.add_action(ccf::tasks::make_basic_action([&]() {
      thread_print("M (after I and D)");
      REQUIRE(executed[3].load());
      REQUIRE(executed[7].load());
      executed[11].store(true);

      tasks_a.add_action(ccf::tasks::make_basic_action([&]() {
        thread_print("N (after M and C)");
        REQUIRE(executed[2].load());
        REQUIRE(executed[11].load());
        executed[12].store(true);

        tasks_c.add_action(ccf::tasks::make_basic_action([&]() {
          thread_print("O (after N)");
          REQUIRE(executed[12].load());
          executed[13].store(true);
        }));
      }));
    }));
  }));

  {
    INFO("Execution loop");

    ccf::tasks::ThreadManager thread_manager(job_board);
    thread_manager.set_task_threads(8);

    using TClock = std::chrono::steady_clock;
    auto now = TClock::now();
    std::chrono::seconds max_run_time(5);
    const auto end_time = now + max_run_time;

    while (true)
    {
      const auto complete =
        std::all_of(std::begin(executed), std::end(executed), [](auto&& e) {
          return e.load();
        });

      if (complete)
      {
        break;
      }

      now = TClock::now();
      if (now > end_time)
      {
        throw std::runtime_error(
          fmt::format("Test did not complete after {}", max_run_time));
      }

      std::this_thread::yield();
    }
  }
}
