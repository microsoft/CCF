// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/basic_task.h"
#include "tasks/job_board.h"
#include "tasks/ordered_tasks.h"
#include "tasks/sub_task_queue.h"

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

void worker(ccf::tasks::IJobBoard& job_board, std::atomic<bool>& stop)
{
  while (!stop.load())
  {
    auto task = job_board.get_task();
    if (task != nullptr)
    {
      task->do_task();
    }
    std::this_thread::yield();
  }
}

void flush_board(
  ccf::tasks::IJobBoard& job_board,
  size_t max_workers = 8,
  std::chrono::seconds stop_after = std::chrono::seconds(5),
  std::chrono::seconds at_least = std::chrono::seconds(1))
{
  std::atomic<bool> stop_signal{false};

  std::vector<std::thread> workers;
  for (size_t i = 0; i < max_workers; ++i)
  {
    workers.emplace_back(worker, std::ref(job_board), std::ref(stop_signal));
  }

  using TClock = std::chrono::steady_clock;
  auto now = TClock::now();
  const auto min_time = now + at_least;
  const auto end_time = now + stop_after;
  while (true)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    now = TClock::now();
    if (now > end_time)
    {
      break;
    }

    if (now > min_time && job_board.empty())
    {
      break;
    }
  }

  stop_signal.store(true);

  for (auto& worker : workers)
  {
    worker.join();
  }
}

uint8_t thread_name()
{
  return std::hash<std::thread::id>{}(std::this_thread::get_id());
}

void thread_print(const std::string& s)
{
  static std::mutex logging_mutex;
  std::lock_guard<std::mutex> guard(logging_mutex);
  fmt::print("[{:0x}] {}\n", thread_name(), s);
}

void thread_debug_print(const std::string& s)
{
#if false
  fmt::print("[{:0x}]   {}\n", thread_name(), s);
#endif
}

template <typename TIter>
ccf::tasks::Task job_sort(TIter begin, TIter end)
{
  return ccf::tasks::make_basic_task([begin, end]() { std::sort(begin, end); });
}

template <typename TDuration>
ccf::tasks::Task job_sleep(const TDuration& t)
{
  return ccf::tasks::make_basic_task([t]() {
    fmt::print("[{}] I'm going to sleep for {}\n", thread_name(), t);
    std::this_thread::sleep_for(t);
    fmt::print("[{}] I slept for {}\n", thread_name(), t);
  });
}

TEST_CASE("JobBoard")
{
  ccf::tasks::JobBoard jb;

  jb.add_task(job_sleep(std::chrono::seconds(1)));
  jb.add_task(job_sleep(std::chrono::seconds(1)));
  jb.add_task(job_sleep(std::chrono::seconds(1)));
  jb.add_task(job_sleep(std::chrono::seconds(1)));
  jb.add_task(job_sleep(std::chrono::seconds(1)));

  flush_board(jb, 3);

  jb.add_task(job_sleep(std::chrono::seconds(1)));

  flush_board(jb, 3);

  std::vector<int> ns;
  for (size_t i = 0; i < 1'000'000; ++i)
  {
    ns.emplace_back(rand());
  }

  static constexpr auto n_sorters = 10;
  auto batch_size = ns.size() / n_sorters;
  auto begin = ns.begin();
  for (size_t i = 0; i < n_sorters; ++i)
  {
    auto batch_begin = begin + i * batch_size;
    auto batch_end = begin + (i + 1) * batch_size;
    jb.add_task(job_sort(batch_begin, batch_end));
  }

  fmt::print("Starting mergey sort thing\n");
  flush_board(jb, 4);
  fmt::print("Done\n");
}

// Confirm expected semantics of SubTaskQueue type
TEST_CASE("SubTaskQueue")
{
  ccf::tasks::SubTaskQueue<size_t> fq;

  // push returns true iff queue was previously empty and inactive
  REQUIRE(fq.push(1));
  REQUIRE_FALSE(fq.push(2));
  REQUIRE_FALSE(fq.push(3));
  REQUIRE_FALSE(fq.push(4));

  // pop returns true iff queue is non-empty when it completes
  REQUIRE_FALSE(fq.pop_and_visit([](size_t&& n) { fmt::print("{}\n", n); }));

  // Visits an empty queue, leaves an empty queue
  REQUIRE_FALSE(fq.pop_and_visit([](size_t&& n) { fmt::print("{}\n", n); }));

  // Not the first push _ever_, but the first on an empty queue, so gets a true
  // response
  REQUIRE(fq.push(5));

  // If the visitor (or anything concurrent with it) pushes a new element, then
  // the pop returns true to indicate that queue is now non-empty
  REQUIRE(fq.pop_and_visit([&](size_t&& n) {
    fmt::print("{}\n", n);

    // While popping/visiting, the queue is active
    REQUIRE_FALSE(fq.push(6));
  }));

  REQUIRE(fq.pop_and_visit([&](size_t&& n) {
    fmt::print("{}\n", n);
    REQUIRE_FALSE(fq.push(7));
    REQUIRE_FALSE(fq.push(8));
    REQUIRE_FALSE(fq.push(9));
  }));

  REQUIRE_FALSE(fq.pop_and_visit([&](size_t&& n) { fmt::print("{}\n", n); }));
}

// TODO: Add some assertions that dependency order is preserved, and test across
// different counts of worker threads
TEST_CASE("OrderedTasks")
{
  ccf::tasks::JobBoard jb;

  auto p_a = ccf::tasks::make_ordered_tasks(jb);
  auto p_b = ccf::tasks::make_ordered_tasks(jb);
  auto p_c = ccf::tasks::make_ordered_tasks(jb);

  ccf::tasks::OrderedTasks& tasks_a = *p_a;
  tasks_a.add_action(ccf::tasks::make_basic_action(
    []() { thread_print("A (no dependencies)"); }));
  tasks_a.add_action(
    ccf::tasks::make_basic_action([]() { thread_print("B (after A)"); }));
  tasks_a.add_action(
    ccf::tasks::make_basic_action([]() { thread_print("C (after B)"); }));

  ccf::tasks::OrderedTasks& tasks_b = *p_b;
  tasks_b.add_action(ccf::tasks::make_basic_action([&tasks_b]() {
    thread_print("D (no dependencies)");
    tasks_b.add_action(ccf::tasks::make_basic_action([&tasks_b]() {
      thread_print("E (after D)");
      tasks_b.add_action(ccf::tasks::make_basic_action([&tasks_b]() {
        thread_print("F (after E)");
        tasks_b.add_action(ccf::tasks::make_basic_action(
          [&tasks_b]() { thread_print("G (after F)"); }));
      }));
    }));
  }));

  ccf::tasks::OrderedTasks& tasks_c = *p_c;
  tasks_c.add_action(
    ccf::tasks::make_basic_action([&tasks_a, &tasks_b, &tasks_c]() {
      thread_print("I (no dependencies)");

      tasks_a.add_action(ccf::tasks::make_basic_action([&tasks_a, &tasks_c]() {
        thread_print("J (after I and C)");
        tasks_a.add_action(ccf::tasks::make_basic_action([&tasks_c]() {
          thread_print("K (after J)");
          tasks_c.add_action(ccf::tasks::make_basic_action(
            []() { thread_print("L (after K)"); }));
        }));
      }));

      tasks_b.add_action(ccf::tasks::make_basic_action([&tasks_a, &tasks_c]() {
        thread_print("M (after I and D)");
        tasks_a.add_action(ccf::tasks::make_basic_action([&tasks_c]() {
          thread_print("N (after M and C)");
          tasks_c.add_action(ccf::tasks::make_basic_action(
            []() { thread_print("O (after N)"); }));
        }));
      }));
    }));

  flush_board(jb, 8);
}
