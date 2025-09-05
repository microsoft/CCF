// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <condition_variable>
#include <doctest/doctest.h>
#include <iostream>
#include <numeric>

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>

TEST_CASE("TaskSystem" * doctest::test_suite("basic_tasks"))
{
  constexpr auto short_wait = std::chrono::milliseconds(10);

  // There's a global singleton job board, initially empty
  auto& job_board = ccf::tasks::get_main_job_board();

  REQUIRE(job_board.empty());
  REQUIRE(job_board.get_task() == nullptr);
  REQUIRE(job_board.wait_for_task(short_wait) == nullptr);

  // Encapsulate the work to be done in Tasks
  // Either as a lambda passed to make_basic_task
  std::atomic<bool> a = false;
  ccf::tasks::Task toggle_a =
    ccf::tasks::make_basic_task([&a]() { a.store(true); });

  // Or by extending BaseTask
  struct SetAtomic : public ccf::tasks::BaseTask
  {
    std::atomic<bool>& my_var;

    SetAtomic(std::atomic<bool>& v) : my_var(v) {}

    void do_task_implementation() override
    {
      my_var.store(true);
    }

    std::string get_name() const override
    {
      return "SetAtomic Task";
    }
  };

  std::atomic<bool> b = false;
  ccf::tasks::Task toggle_b = std::make_shared<SetAtomic>(b);

  // These tasks aren't scheduled yet, and can't have been executed!
  REQUIRE(job_board.empty());
  REQUIRE_FALSE(a.load());
  REQUIRE_FALSE(b.load());

  // Queue them on a job board, where a worker can find them
  ccf::tasks::add_task(toggle_a);
  ccf::tasks::add_task(toggle_b);

  // Now there's something scheduled
  REQUIRE_FALSE(job_board.empty());

  // But it's not _executed_ yet
  REQUIRE_FALSE(a.load());
  REQUIRE_FALSE(b.load());

  // Eventually something like a dedicated worker thread arrives, and asks for a
  // task
  auto first_task = job_board.get_task();

  // They likely take things one-at-a-time, so there's still something scheduled
  REQUIRE_FALSE(job_board.empty());

  // Not a critical guarantee, but for now the job board is FIFO, so in this
  // constrained example we know exactly what the task is
  REQUIRE(first_task == toggle_a);

  // This caller has taken ownership of this task, and is now responsible for
  // executing it
  REQUIRE_FALSE(a.load());
  first_task->do_task();
  REQUIRE(a.load());

  // Then someone, maybe the same worker, arrives and takes the second task
  auto second_task = job_board.get_task();
  REQUIRE(second_task == toggle_b);
  REQUIRE(job_board.empty());

  REQUIRE_FALSE(b.load());
  second_task->do_task();
  REQUIRE(b.load());
}

TEST_CASE("Cancellation" * doctest::test_suite("basic_tasks"))
{
  // If you keep a handle to a task, you can cancel it...
  std::atomic<bool> a = false;
  ccf::tasks::Task toggle_a =
    ccf::tasks::make_basic_task([&a]() { a.store(true); });

  // ... even after it has been scheduled
  ccf::tasks::add_task(toggle_a);

  // ... at any point until some worker calls do_task
  auto first_task = ccf::tasks::get_main_job_board().get_task();
  REQUIRE(first_task != nullptr);

  REQUIRE_FALSE(a.load());
  toggle_a->cancel_task();
  first_task->do_task();
  REQUIRE_FALSE(a.load());
}

TEST_CASE("Scheduling" * doctest::test_suite("basic_tasks"))
{
  // Tasks can be scheduled from anywhere, including during execution of
  // other tasks
  struct WaitPoint
  {
    std::atomic<bool> passed{false};

    void wait()
    {
      while (!passed.load())
      {
        std::this_thread::yield();
      }
    }

    void notify()
    {
      passed.store(true);
    }
  };

  WaitPoint a_started;
  WaitPoint b_started;
  WaitPoint task_0_started;
  WaitPoint task_1_started;
  WaitPoint task_2_started;
  WaitPoint task_3_started;
  WaitPoint task_4_started;
  WaitPoint task_5_started;

  std::atomic<bool> stop_signal = false;
  std::vector<size_t> count_with_me;

  std::thread thread_a([&]() {
    count_with_me.push_back(0);
    a_started.notify();

    ccf::tasks::add_task(ccf::tasks::make_basic_task([&]() {
      task_1_started.wait();
      count_with_me.push_back(2);
      task_2_started.notify();

      ccf::tasks::add_task(ccf::tasks::make_basic_task([&]() {
        task_3_started.wait();
        count_with_me.push_back(4);
        task_4_started.notify();

        ccf::tasks::add_task(ccf::tasks::make_basic_task([&]() {
          task_5_started.wait();
          count_with_me.push_back(6);
          stop_signal.store(true);
        }));
      }));
    }));
  });

  std::thread thread_b([&]() {
    a_started.wait();

    ccf::tasks::add_task(ccf::tasks::make_basic_task([&]() {
      count_with_me.push_back(1);
      task_1_started.notify();

      ccf::tasks::add_task(ccf::tasks::make_basic_task([&]() {
        task_4_started.wait();
        count_with_me.push_back(5);
        task_5_started.notify();
      }));

      ccf::tasks::add_task(ccf::tasks::make_basic_task([&]() {
        task_2_started.wait();
        count_with_me.push_back(3);
        task_3_started.notify();
      }));
    }));
  });

  auto worker_fn = [&]() {
    while (!stop_signal.load())
    {
      auto task = ccf::tasks::get_main_job_board().wait_for_task(
        std::chrono::milliseconds(100));
      if (task != nullptr)
      {
        task->do_task();
      }
    }
  };

  std::vector<std::thread> workers;
  for (size_t i = 0; i < 2; ++i)
  {
    workers.emplace_back(worker_fn);
  }

  for (auto& worker : workers)
  {
    worker.join();
  }

  thread_a.join();
  thread_b.join();

  decltype(count_with_me) target(7);
  std::iota(target.begin(), target.end(), 0);
  REQUIRE(count_with_me == target);
}
