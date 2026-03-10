// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/basic_task.h"
#include "tasks/task_system.h"
#include "tasks/worker.h"

#include <doctest/doctest.h>
#include <iostream>
#include <numeric>
#include <thread>

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>

TEST_CASE("JobBoard" * doctest::test_suite("basic_tasks"))
{
  constexpr auto short_wait = std::chrono::milliseconds(10);

  ccf::tasks::JobBoard job_board;
  ccf::tasks::JobBoard::Summary empty_board{};

  REQUIRE(job_board.get_summary() == empty_board);
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

    const std::string& get_name() const override
    {
      static const std::string name = "SetAtomic";
      return name;
    }
  };

  std::atomic<bool> b = false;
  ccf::tasks::Task toggle_b = std::make_shared<SetAtomic>(b);

  // These tasks aren't scheduled yet, and can't have been executed!
  REQUIRE(job_board.get_summary() == empty_board);
  REQUIRE_FALSE(a.load());
  REQUIRE_FALSE(b.load());

  // Queue them on a job board, where a worker can find them
  job_board.add_task(toggle_a);
  job_board.add_task(toggle_b);

  // Now there's something scheduled
  REQUIRE(job_board.get_summary().pending_tasks == 2);

  // But it's not _executed_ yet
  REQUIRE_FALSE(a.load());
  REQUIRE_FALSE(b.load());

  // Eventually something like a dedicated worker thread arrives, and asks for a
  // task
  auto first_task = job_board.get_task();

  // They likely take things one-at-a-time, so there's still something scheduled
  REQUIRE(job_board.get_summary().pending_tasks == 1);

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
  REQUIRE(job_board.get_summary() == empty_board);

  REQUIRE_FALSE(b.load());
  second_task->do_task();
  REQUIRE(b.load());
}

TEST_CASE("Cancellation" * doctest::test_suite("basic_tasks"))
{
  ccf::tasks::JobBoard job_board;

  // If you keep a handle to a task, you can cancel it...
  std::atomic<bool> a = false;
  ccf::tasks::Task toggle_a =
    ccf::tasks::make_basic_task([&a]() { a.store(true); });

  // ... even after it has been scheduled
  job_board.add_task(toggle_a);

  // ... at any point until some worker calls do_task
  auto first_task = job_board.get_task();
  REQUIRE(first_task != nullptr);

  REQUIRE_FALSE(a.load());
  toggle_a->cancel_task();
  first_task->do_task();
  REQUIRE_FALSE(a.load());
}

TEST_CASE("Scheduling" * doctest::test_suite("basic_tasks"))
{
  ccf::tasks::JobBoard job_board;

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

    job_board.add_task(ccf::tasks::make_basic_task([&]() {
      task_1_started.wait();
      count_with_me.push_back(2);
      task_2_started.notify();

      job_board.add_task(ccf::tasks::make_basic_task([&]() {
        task_3_started.wait();
        count_with_me.push_back(4);
        task_4_started.notify();

        job_board.add_task(ccf::tasks::make_basic_task([&]() {
          task_5_started.wait();
          count_with_me.push_back(6);
          stop_signal.store(true);
        }));
      }));
    }));
  });

  std::thread thread_b([&]() {
    a_started.wait();

    job_board.add_task(ccf::tasks::make_basic_task([&]() {
      count_with_me.push_back(1);
      task_1_started.notify();

      job_board.add_task(ccf::tasks::make_basic_task([&]() {
        task_4_started.wait();
        count_with_me.push_back(5);
        task_5_started.notify();
      }));

      job_board.add_task(ccf::tasks::make_basic_task([&]() {
        task_2_started.wait();
        count_with_me.push_back(3);
        task_3_started.notify();
      }));
    }));
  });

  auto worker_fn = [&]() {
    while (!stop_signal.load())
    {
      auto task = job_board.wait_for_task(std::chrono::milliseconds(100));
      if (task != nullptr)
      {
        task->do_task();
      }
    }
  };

  std::vector<std::thread> workers;

  // Potentially 3 parallel jobs => need at least 3 workers
  for (size_t i = 0; i < 3; ++i)
  {
    workers.emplace_back(worker_fn);
  }

  std::thread watchdog([&]() {
    using Clock = std::chrono::steady_clock;
    auto start = Clock::now();
    while (!stop_signal.load())
    {
      auto now = Clock::now();
      auto elapsed = now - start;
      REQUIRE(elapsed < std::chrono::seconds(1));
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  for (auto& worker : workers)
  {
    worker.join();
  }

  thread_a.join();
  thread_b.join();

  watchdog.join();

  decltype(count_with_me) target(7);
  std::iota(target.begin(), target.end(), 0);
  REQUIRE(count_with_me == target);
}

// Call chains for stack trace verification. noinline ensures each
// function survives as a distinct frame in optimised builds.
namespace exception_handling_test
{
  __attribute__((noinline)) void level_3_throws_runtime_error()
  {
    throw std::runtime_error("Test exception");
  }

  __attribute__((noinline)) void level_2_calls_level_3()
  {
    level_3_throws_runtime_error();
  }

  __attribute__((noinline)) void level_1_calls_level_2()
  {
    level_2_calls_level_3();
  }

  __attribute__((noinline)) void level_3_throws_int()
  {
    throw 42;
  }

  __attribute__((noinline)) void level_2_calls_level_3_int()
  {
    level_3_throws_int();
  }

  __attribute__((noinline)) void level_1_calls_level_2_int()
  {
    level_2_calls_level_3_int();
  }

  struct ThrowsException : public ccf::tasks::BaseTask
  {
    void do_task_implementation() override
    {
      level_1_calls_level_2();
    }

    const std::string& get_name() const override
    {
      static const std::string name = "ThrowsException";
      return name;
    }
  };

  struct ThrowsUnknown : public ccf::tasks::BaseTask
  {
    void do_task_implementation() override
    {
      level_1_calls_level_2_int();
    }

    const std::string& get_name() const override
    {
      static const std::string name = "ThrowsUnknown";
      return name;
    }
  };
}

TEST_CASE("Exception handling" * doctest::test_suite("basic_tasks"))
{
  // Custom logger that captures log messages for assertion
  struct CapturingLogger : public ccf::logger::AbstractLogger
  {
    std::mutex mutex;
    std::vector<std::string> messages;

    void write(const ccf::logger::LogLine& ll) override
    {
      std::lock_guard<std::mutex> lock(mutex);
      messages.push_back(ll.msg);
    }

    bool contains(const std::string& substring)
    {
      std::lock_guard<std::mutex> lock(mutex);
      for (const auto& m : messages)
      {
        if (m.find(substring) != std::string::npos)
        {
          return true;
        }
      }
      return false;
    }

    void clear()
    {
      std::lock_guard<std::mutex> lock(mutex);
      messages.clear();
    }
  };

  auto capturing_logger = std::make_unique<CapturingLogger>();
  auto* logger_ptr = capturing_logger.get();
  ccf::logger::config::loggers().push_back(std::move(capturing_logger));

  // Task that runs successfully after exceptions
  std::atomic<bool> success_task_ran = false;
  ccf::tasks::Task success_task = ccf::tasks::make_basic_task(
    [&success_task_ran]() { success_task_ran.store(true); }, "SuccessTask");

  ccf::tasks::JobBoard job_board;
  std::atomic<bool> stop_signal = false;

  // Queue tasks: two that throw, then one that should still run
  job_board.add_task(
    std::make_shared<exception_handling_test::ThrowsException>());
  job_board.add_task(
    std::make_shared<exception_handling_test::ThrowsUnknown>());
  job_board.add_task(success_task);

  std::thread worker([&]() {
    ccf::tasks::task_worker_loop(
      job_board, stop_signal, /*abort_on_throw=*/false);
  });

  // Wait for the success task to run
  const auto wait_step = std::chrono::milliseconds(10);
  const auto max_wait = std::chrono::seconds(5);
  auto waited = std::chrono::milliseconds(0);
  while (!success_task_ran.load() && waited < max_wait)
  {
    std::this_thread::sleep_for(wait_step);
    waited += wait_step;
  }

  stop_signal.store(true);
  worker.join();

  // With CCF_TASK_EXCEPTION_NO_ABORT, the worker loop continues after
  // exceptions, so the success task should have run
  REQUIRE(success_task_ran.load());

  // Verify that fatal messages were logged for both exception types
  REQUIRE(logger_ptr->contains(
    "ThrowsException task failed with exception: Test exception"));
  REQUIRE(
    logger_ptr->contains("ThrowsUnknown task failed with unknown exception"));

  // Verify demangled function names appear in the stack traces
#ifndef NDEBUG
  // ThrowsException call chain
  REQUIRE(logger_ptr->contains("level_3_throws_runtime_error"));
  REQUIRE(logger_ptr->contains("level_2_calls_level_3"));
  REQUIRE(logger_ptr->contains("level_1_calls_level_2"));

  // ThrowsUnknown call chain
  REQUIRE(logger_ptr->contains("level_2_calls_level_3_int"));
  REQUIRE(logger_ptr->contains("level_1_calls_level_2_int"));
#endif

  // Clean up: remove the capturing logger
  auto& loggers = ccf::logger::config::loggers();
  loggers.erase(
    std::remove_if(
      loggers.begin(),
      loggers.end(),
      [logger_ptr](const auto& l) { return l.get() == logger_ptr; }),
    loggers.end());
}
