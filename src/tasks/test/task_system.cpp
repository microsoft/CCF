// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/task_system.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <random>
#include <set>
#include <thread>

template <typename T>
struct SetWithLock
{
  std::mutex* m;
  std::set<T>* set;

  SetWithLock()
  {
    m = new std::mutex();
    set = new std::set<T>();
  }

  ~SetWithLock()
  {
    {
      std::lock_guard<std::mutex> lock(*m);
      delete set;
    }
    delete m;
  }

  void add(const T& t)
  {
    std::lock_guard<std::mutex> lock(*m);
    set->insert(t);
  }
};

using ThreadIDs = SetWithLock<std::thread::id>;

static std::thread::id main_thread_id = std::this_thread::get_id();

static std::atomic<size_t> created_tasks = {};
static std::atomic<size_t> completed_tasks = {};
static std::atomic<size_t> cancelled_tasks = {};

std::random_device random_device;
std::mt19937 random_generator(random_device());

struct CompletionCountingTask : public ccf::tasks::Task
{
  CompletionCountingTask()
  {
    ++created_tasks;
  }

  void after_task_cb(bool cancelled) override
  {
    // Confirm that all after_task callbacks occur on the main thread
    REQUIRE(std::this_thread::get_id() == main_thread_id);

    ++completed_tasks;

    if (cancelled)
    {
      ++cancelled_tasks;
    }
  }
};

struct ThreadIDCountingTask : public CompletionCountingTask
{
  ThreadIDs& thread_ids;

  ThreadIDCountingTask(ThreadIDs& thread_ids_) :
    CompletionCountingTask(),
    thread_ids(thread_ids_)
  {}

  void execute_task() override
  {
    thread_ids.add(std::this_thread::get_id());
  }
};

template <size_t N>
struct RecursiveThreadIDCountingTask : public ThreadIDCountingTask
{
  RecursiveThreadIDCountingTask(ThreadIDs& thread_ids_) :
    ThreadIDCountingTask(thread_ids_)
  {}

  void execute_task() override
  {
    // Confirm that inside a task, we can queue other tasks
    if constexpr (N == 0)
    {
      ccf::tasks::TaskSystem::enqueue_task(
        std::make_unique<ThreadIDCountingTask>(thread_ids));
    }
    else
    {
      ccf::tasks::TaskSystem::enqueue_task(
        std::make_unique<RecursiveThreadIDCountingTask<N - 1>>(thread_ids));
    }

    // Note that we queue before our own execution completes, so it could occur
    // first!
    ThreadIDCountingTask::execute_task();
  }
};

using Tasks = std::vector<std::unique_ptr<ccf::tasks::Task>>;
using TaskHandles = std::vector<ccf::tasks::TaskHandle>;

TaskHandles shuffle_and_submit(Tasks&& tasks)
{
  TaskHandles handles;
  std::shuffle(tasks.begin(), tasks.end(), random_generator);

  for (auto&& task : tasks)
  {
    handles.emplace_back(ccf::tasks::TaskSystem::enqueue_task(std::move(task)));
  }

  return handles;
}

void run()
{
  ccf::tasks::TaskSystem::run_for(std::chrono::milliseconds(100));
}

using Canceller = std::function<void(TaskHandles&&)>;

template <typename T>
void run_n_thread_counting_tasks(size_t n, Canceller&& canceller = nullptr)
{
  created_tasks.store(0);
  completed_tasks.store(0);
  cancelled_tasks.store(0);

  ThreadIDs thread_ids;
  Tasks tasks;

  for (size_t i = 0; i < n; ++i)
  {
    tasks.emplace_back(std::make_unique<T>(thread_ids));
  }

  auto handles = shuffle_and_submit(std::move(tasks));

  if (canceller)
  {
    canceller(std::move(handles));
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE(created_tasks.load() > 0);
  REQUIRE(completed_tasks.load() == 0);

  run();

  const auto created = created_tasks.load();
  const auto completed = completed_tasks.load();
  const auto cancelled = cancelled_tasks.load();

  fmt::print(
    "Completed a test: {}/{} tasks completed, and {} cancelled\n",
    completed,
    created,
    cancelled);

  REQUIRE(completed == created);

  REQUIRE(cancelled <= completed);

  if (!canceller)
  {
    REQUIRE(cancelled == 0);
  }

  // We can assert very little about how many threads were actually seen! We
  // hope it increases with the number of tasks until it reaches the thread
  // pool size, but this is up to a scheduler that is out of our control. The
  // only thing we want to enforce here is that some work happened on something
  // other than the main thread.
  thread_ids.set->erase(main_thread_id);
  REQUIRE(thread_ids.set->size() > 0);
}

TEST_CASE("Basic")
{
  std::vector<size_t> n_tasks = {1, 4, 16, 64};

  for (auto n : n_tasks)
  {
    run_n_thread_counting_tasks<ThreadIDCountingTask>(n);
  }
}

TEST_CASE("Recursive tasks")
{
  std::vector<size_t> n_tasks = {1, 4, 16, 64};

  for (auto n : n_tasks)
  {
    run_n_thread_counting_tasks<RecursiveThreadIDCountingTask<1>>(n);
  }
}

TEST_CASE("Deeply recursive tasks")
{
  std::vector<size_t> n_tasks = {1, 4, 16, 64};

  for (auto n : n_tasks)
  {
    run_n_thread_counting_tasks<RecursiveThreadIDCountingTask<100>>(n);
  }
}

TEST_CASE("Cancellation - basic")
{
  static constexpr auto n_tasks = 64;
  using BasicTaskType = RecursiveThreadIDCountingTask<100>;

  // Cancel some tasks before they begin
  run_n_thread_counting_tasks<BasicTaskType>(
    n_tasks, [](TaskHandles&& handles) {
      REQUIRE(handles.size() == n_tasks);

      std::uniform_int_distribution<> distrib(1, n_tasks);
      const auto to_cancel = distrib(random_generator);

      for (size_t i = 0; i < to_cancel; ++i)
      {
        ccf::tasks::TaskSystem::cancel_task(std::move(handles[i]));
      }
    });
}

struct ChaoticCancellerTask : public CompletionCountingTask
{
  TaskHandles candidates;

  ChaoticCancellerTask(TaskHandles&& candidates_) : candidates(candidates_) {}

  void execute_task()
  {
    // (Try to) cancel half of the candidate
    for (auto&& handle : candidates)
    {
      if (rand() % 2 == 0)
      {
        ccf::tasks::TaskSystem::cancel_task(std::move(handle));
      }
    }
  }
};

TEST_CASE("Cancellation - dynamic")
{
  static constexpr auto n_tasks = 2000;
  using BasicTaskType = ThreadIDCountingTask;

  // Insert some tasks which, when executed, will try to cancel other tasks.
  run_n_thread_counting_tasks<BasicTaskType>(
    n_tasks, [](TaskHandles&& handles) {
      REQUIRE(handles.size() == n_tasks);

      std::uniform_int_distribution<> distrib(1, n_tasks / 10);
      const auto num_cancellation_tasks = distrib(random_generator);
      const auto range_per_task = handles.size() / num_cancellation_tasks;

      auto range_start = handles.begin();
      auto range_end = range_start + range_per_task;
      for (size_t i = 0; i < num_cancellation_tasks; ++i)
      {
        TaskHandles candidates(range_start, range_end);
        ccf::tasks::TaskSystem::enqueue_task(
          std::make_unique<ChaoticCancellerTask>(std::move(candidates)));

        range_start = range_end;
        range_end += range_per_task;
      }
    });
}

int main(int argc, char** argv)
{
  ccf::tasks::TaskSystem::init();

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}