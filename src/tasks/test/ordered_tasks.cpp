// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/ordered_tasks.h"

#include "ccf/ds/locking.h"
#include "tasks/basic_task.h"
#include "tasks/sub_task_queue.h"
#include "tasks/thread_manager.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#define FMT_HEADER_ONLY
#include <deque>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <latch>
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
  static ccf::ds::Mutex logging_mutex;
  ccf::ds::MutexGuard guard(logging_mutex);
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

TEST_CASE(
  "Concurrent pause + add_action does not double-enqueue" *
  doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::JobBoard job_board;
  auto tasks = ccf::tasks::OrderedTasks::create(job_board);

  std::vector<size_t> execution_order;

  // Step 1: Add an action that pauses itself mid-execution
  ccf::tasks::Resumable resumable;

  tasks->add_action(ccf::tasks::make_basic_action([&]() {
    execution_order.push_back(1);

    // Pause the task (simulating respond_on_commit)
    resumable = ccf::tasks::pause_current_task();
  }));

  // Step 2: Execute the first action - it will pause
  {
    auto task = job_board.get_task();
    REQUIRE(task != nullptr);
    task->do_task();
  }

  // Confirm results of action - board should be empty, and we hold a resumable
  // token to restore the paused queue
  REQUIRE(job_board.get_task() == nullptr);
  REQUIRE(resumable != nullptr);

  // Step 3: Simulate concurrent operations - add_action + resume_task
  tasks->add_action(
    ccf::tasks::make_basic_action([&]() { execution_order.push_back(2); }));

  ccf::tasks::resume_task(std::move(resumable));

  // Step 4: Count how many times the task was enqueued
  size_t enqueue_count = 0;
  while (true)
  {
    auto task = job_board.get_task();
    if (task == nullptr)
    {
      break;
    }
    enqueue_count++;
    task->do_task();
  }

  // Confirm that despite 2 potentially-queuing concurrent operations, only one
  // actual enqueue occurred
  REQUIRE(enqueue_count == 1);

  // Verify the second action (added in step 3) actually executed
  REQUIRE(execution_order == std::vector<size_t>{1, 2});
}

namespace
{
  struct ShutdownOwner
  {
    std::shared_ptr<ccf::tasks::OrderedTasks> tasks;

    ~ShutdownOwner()
    {
      tasks->cancel_task();
    }
  };

  struct ShutdownAction : public ccf::tasks::ITaskAction
  {
    std::shared_ptr<ShutdownOwner> owner;
    size_t notifications = 0;
    size_t executions = 0;

    void do_action() override
    {
      ++executions;
    }

    void on_shutdown() noexcept override
    {
      ++notifications;
      owner.reset();
    }

    const std::string& get_name() const override
    {
      static const std::string name = "ShutdownAction";
      return name;
    }
  };
}

TEST_CASE(
  "Shutdown breaks ready and paused ownership cycles" *
  doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::JobBoard board;
  auto tasks = ccf::tasks::OrderedTasks::create(board);
  auto owner = std::make_shared<ShutdownOwner>();
  owner->tasks = tasks;
  auto action = std::make_shared<ShutdownAction>();
  action->owner = owner;
  std::weak_ptr<ShutdownOwner> weak_owner = owner;
  std::weak_ptr<ccf::tasks::OrderedTasks> weak_tasks = tasks;
  ccf::tasks::Resumable resumable;

  SUBCASE("Ready")
  {
    tasks->add_action(action);
    REQUIRE(board.get_summary().pending_tasks == 1);
  }
  SUBCASE("Cancelled but still owning actions")
  {
    tasks->add_action(action);
    tasks->cancel_task();
    auto scheduled = board.get_task();
    scheduled->do_task();
    REQUIRE(board.get_summary().pending_tasks == 0);
  }
  SUBCASE("Paused with an unexecuted local batch")
  {
    tasks->add_action(ccf::tasks::make_basic_action(
      [&]() { resumable = ccf::tasks::pause_current_task(); }));
    tasks->add_action(action);
    auto scheduled = board.get_task();
    scheduled->do_task();
    REQUIRE(resumable != nullptr);
    REQUIRE(board.get_summary().pending_tasks == 0);
  }

  tasks.reset();
  owner.reset();
  REQUIRE_FALSE(weak_owner.expired());
  REQUIRE_FALSE(weak_tasks.expired());
  REQUIRE(board.get_summary().registered_tasks == 1);

  board.shutdown();
  REQUIRE(weak_owner.expired());
  REQUIRE(action->notifications == 1);
  REQUIRE(action->executions == 0);
  REQUIRE(board.get_summary().registered_tasks == 0);
  if (resumable != nullptr)
  {
    // A late commit callback must not resurrect the paused queue.
    ccf::tasks::resume_task(std::move(resumable));
  }
  REQUIRE(weak_tasks.expired());
  REQUIRE(board.get_task() == nullptr);
  board.shutdown();
  REQUIRE(action->notifications == 1);
}

TEST_CASE(
  "Shutdown releases closure captures without external owners" *
  doctest::test_suite("ordered_tasks"))
{
  std::weak_ptr<ShutdownOwner> weak_owner;
  std::weak_ptr<ccf::tasks::OrderedTasks> weak_tasks;
  {
    ccf::tasks::JobBoard board;
    auto tasks = ccf::tasks::OrderedTasks::create(board);
    auto owner = std::make_shared<ShutdownOwner>();
    owner->tasks = tasks;
    weak_owner = owner;
    weak_tasks = tasks;
    tasks->add_action(ccf::tasks::make_basic_action(
      [owner]() { FAIL("An abandoned action must not execute"); }));
    owner.reset();
    tasks.reset();
    REQUIRE_FALSE(weak_owner.expired());
    REQUIRE_FALSE(weak_tasks.expired());
    // The board destructor must also shut down, rather than simply release
    // its ready queue and leave a now-unreachable ownership cycle behind.
  }
  REQUIRE(weak_owner.expired());
  REQUIRE(weak_tasks.expired());
}

TEST_CASE(
  "Shutdown registry does not retain completed schedulers" *
  doctest::test_suite("ordered_tasks"))
{
  auto board = std::make_unique<ccf::tasks::JobBoard>();
  for (size_t i = 0; i < 100; ++i)
  {
    auto tasks = ccf::tasks::OrderedTasks::create(*board);
    std::weak_ptr<ccf::tasks::OrderedTasks> weak_tasks = tasks;
    REQUIRE(board->get_summary().registered_tasks == 1);
    tasks.reset();
    REQUIRE(weak_tasks.expired());
    REQUIRE(board->get_summary().registered_tasks == 0);
  }
  auto survivor = ccf::tasks::OrderedTasks::create(*board);
  board.reset();
  REQUIRE(survivor->is_shutdown());
  survivor.reset();
}

TEST_CASE(
  "Shutdown releases externally retained closure captures" *
  doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::JobBoard board;
  auto tasks = ccf::tasks::OrderedTasks::create(board);
  SUBCASE("Queued before shutdown") {}
  SUBCASE("Submitted after shutdown")
  {
    board.shutdown();
  }
  auto marker = std::make_shared<int>(42);
  std::weak_ptr<int> weak_marker = marker;
  auto task = ccf::tasks::make_basic_task(
    [marker]() { FAIL("An abandoned task must not execute"); });
  auto action = ccf::tasks::make_basic_action(
    [marker]() { FAIL("An abandoned action must not execute"); });
  marker.reset();
  REQUIRE_FALSE(weak_marker.expired());
  board.add_task(task);
  tasks->add_action(ccf::tasks::TaskAction{action});
  board.shutdown();
  REQUIRE(weak_marker.expired());
  REQUIRE(task != nullptr);
  REQUIRE(action != nullptr);
}

TEST_CASE(
  "Shutdown rejects late actions and new schedulers" *
  doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::JobBoard board;
  auto tasks = ccf::tasks::OrderedTasks::create(board);
  board.shutdown();

  auto late_action = std::make_shared<ShutdownAction>();
  tasks->add_action(late_action);
  REQUIRE(late_action->notifications == 1);
  REQUIRE(late_action->executions == 0);

  auto late_tasks = ccf::tasks::OrderedTasks::create(board);
  REQUIRE(late_tasks->is_shutdown());
  auto another_action = std::make_shared<ShutdownAction>();
  late_tasks->add_action(another_action);
  REQUIRE(another_action->notifications == 1);
  REQUIRE(board.get_summary().registered_tasks == 0);
  REQUIRE(board.get_task() == nullptr);
}

TEST_CASE(
  "Shutdown cleanup can re-enter task APIs" *
  doctest::test_suite("ordered_tasks"))
{
  ccf::tasks::JobBoard board;
  auto tasks = ccf::tasks::OrderedTasks::create(board);
  struct ReentrantCleanup
  {
    ccf::tasks::JobBoard& board;
    std::shared_ptr<ccf::tasks::OrderedTasks> tasks;
    std::shared_ptr<ShutdownAction> late_action;
    size_t& destroyed;

    ~ReentrantCleanup()
    {
      ++destroyed;
      board.shutdown();
      tasks->shutdown();
      tasks->add_action(late_action);
      board.add_task(ccf::tasks::make_basic_task(
        []() { FAIL("Cleanup must not schedule executable work"); }));
      board.add_delayed_task(
        ccf::tasks::make_basic_task(
          []() { FAIL("Cleanup must not schedule delayed work"); }),
        std::chrono::milliseconds(1));
      board.add_periodic_task(
        ccf::tasks::make_basic_task(
          []() { FAIL("Cleanup must not schedule periodic work"); }),
        std::chrono::milliseconds(1),
        std::chrono::milliseconds(1));
    }
  };
  size_t destroyed = 0;
  auto late_action = std::make_shared<ShutdownAction>();
  auto cleanup =
    std::make_shared<ReentrantCleanup>(board, tasks, late_action, destroyed);
  tasks->add_action(ccf::tasks::make_basic_action([cleanup]() {}));
  cleanup.reset();

  board.shutdown();
  REQUIRE(destroyed == 1);
  REQUIRE(late_action->notifications == 1);
  board.tick(std::chrono::milliseconds(10));
  REQUIRE(board.get_task() == nullptr);
}

TEST_CASE(
  "Shutdown notifies ready delayed and periodic tasks once" *
  doctest::test_suite("ordered_tasks"))
{
  struct ShutdownTask : public ccf::tasks::BaseTask
  {
    size_t notifications = 0;
    void on_shutdown() noexcept override
    {
      ++notifications;
    }
    void do_task_implementation() override
    {
      FAIL("A shutdown task must not execute");
    }
    const std::string& get_name() const override
    {
      static const std::string name = "ShutdownTask";
      return name;
    }
  };
  ccf::tasks::JobBoard board;
  auto task = std::make_shared<ShutdownTask>();
  board.add_task(task);
  board.add_delayed_task(task, std::chrono::milliseconds(1));
  board.add_periodic_task(
    task, std::chrono::milliseconds(1), std::chrono::milliseconds(1));
  board.shutdown();
  REQUIRE(task->notifications == 1);
  REQUIRE(task->is_cancelled());
  task->do_task();
  board.tick(std::chrono::milliseconds(10));
  REQUIRE(board.get_task() == nullptr);
  board.add_task(task);
  board.add_delayed_task(task, std::chrono::milliseconds(1));
  REQUIRE(task->notifications == 1);
}

TEST_CASE(
  "Concurrent shutdown notifies each task once" *
  doctest::test_suite("ordered_tasks"))
{
  struct CountingTask : public ccf::tasks::BaseTask
  {
    std::atomic<size_t> notifications = 0;
    void on_shutdown() noexcept override
    {
      ++notifications;
    }
    void do_task_implementation() override {}
    const std::string& get_name() const override
    {
      static const std::string name = "CountingTask";
      return name;
    }
  };

  constexpr size_t num_threads = 8;
  constexpr size_t num_tasks = 1000;
  ccf::tasks::JobBoard board;
  std::vector<std::shared_ptr<CountingTask>> tasks(num_tasks);
  for (auto& task : tasks)
  {
    task = std::make_shared<CountingTask>();
    board.add_task(task);
  }

  // One thread shuts down the board while the others race to shut down the
  // same queued tasks directly.
  std::latch start(num_threads);
  std::vector<std::thread> threads;
  for (size_t i = 0; i < num_threads; ++i)
  {
    threads.emplace_back([&, i]() {
      start.arrive_and_wait();
      if (i == 0)
      {
        board.shutdown();
        return;
      }
      for (const auto& task : tasks)
      {
        task->shutdown();
      }
    });
  }
  for (auto& thread : threads)
  {
    thread.join();
  }

  size_t miscounted = 0;
  for (const auto& task : tasks)
  {
    if (task->notifications != 1)
    {
      ++miscounted;
    }
  }
  REQUIRE(miscounted == 0);
  REQUIRE(board.get_task() == nullptr);
}
