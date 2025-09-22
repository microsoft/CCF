// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <random>
#include <thread>

#define PICOBENCH_DONT_BIND_TO_ONE_CORE
#include <picobench/picobench.hpp>

struct NopTask : public ccf::tasks::BaseTask
{
  void do_task_implementation() override {}

  std::string_view get_name() const override
  {
    return "NopTask";
  }
};

void enqueue_many(picobench::state& s, size_t thread_count, size_t task_count)
{
  s.start_timer();
  std::vector<std::thread> threads;
  for (auto i = 0; i < thread_count; ++i)
  {
    threads.emplace_back([task_count]() {
      for (auto j = 0; j < task_count; ++j)
      {
        ccf::tasks::add_task(std::make_shared<NopTask>());
        std::this_thread::yield();
      }
    });
  }

  for (auto& thread : threads)
  {
    thread.join();
  }
  s.stop_timer();
}

template <size_t num_threads>
static void benchmark_enqueue(picobench::state& s)
{
  enqueue_many(s, num_threads, s.iterations());
}

struct IncTask : public ccf::tasks::BaseTask
{
  std::atomic<size_t>& value;

  IncTask(std::atomic<size_t>& v) : value(v) {}

  void do_task_implementation() override
  {
    ++value;
  }

  std::string_view get_name() const override
  {
    return "IncTask";
  }
};

void dequeue_many(picobench::state& s, size_t thread_count, size_t task_count)
{
  std::atomic<size_t> tasks_done = 0;
  for (auto j = 0; j < task_count; ++j)
  {
    ccf::tasks::add_task(std::make_shared<IncTask>(tasks_done));
    std::this_thread::yield();
  }

  s.start_timer();
  std::vector<std::thread> threads;
  for (auto i = 0; i < thread_count; ++i)
  {
    threads.emplace_back([task_count, &tasks_done]() {
      if (tasks_done.load() < task_count)
      {
        auto task = ccf::tasks::get_main_job_board().get_task();
        if (task != nullptr)
        {
          task->do_task();
        }
        std::this_thread::yield();
      }
    });
  }

  for (auto& thread : threads)
  {
    thread.join();
  }
  s.stop_timer();
}

template <size_t num_threads>
static void benchmark_dequeue(picobench::state& s)
{
  dequeue_many(s, num_threads, s.iterations());
}

const std::vector<int> task_counts{32'000, 64'000};

namespace
{
  auto enq_1 = benchmark_enqueue<1>;
  auto enq_2 = benchmark_enqueue<2>;
  auto enq_4 = benchmark_enqueue<4>;
  auto enq_8 = benchmark_enqueue<8>;
  auto enq_16 = benchmark_enqueue<16>;
  auto enq_32 = benchmark_enqueue<32>;

  PICOBENCH_SUITE("contended enqueue");
  PICOBENCH(enq_1).iterations(task_counts).baseline();
  PICOBENCH(enq_2).iterations(task_counts);
  PICOBENCH(enq_4).iterations(task_counts);
  PICOBENCH(enq_8).iterations(task_counts);
  PICOBENCH(enq_16).iterations(task_counts);
  PICOBENCH(enq_32).iterations(task_counts);
}

namespace
{
  auto deq_1 = benchmark_dequeue<1>;
  auto deq_2 = benchmark_dequeue<2>;
  auto deq_4 = benchmark_dequeue<4>;
  auto deq_8 = benchmark_dequeue<8>;
  auto deq_16 = benchmark_dequeue<16>;
  auto deq_32 = benchmark_dequeue<32>;

  PICOBENCH_SUITE("contended dequeue");
  PICOBENCH(deq_1).iterations(task_counts).baseline();
  PICOBENCH(deq_2).iterations(task_counts);
  PICOBENCH(deq_4).iterations(task_counts);
  PICOBENCH(deq_8).iterations(task_counts);
  PICOBENCH(deq_16).iterations(task_counts);
  PICOBENCH(deq_32).iterations(task_counts);
}
