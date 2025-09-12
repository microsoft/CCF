// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "./flush_all_tasks.h"
#include "tasks/basic_task.h"

#include <thread>

#define PICOBENCH_DONT_BIND_TO_ONE_CORE
#include <picobench/picobench.hpp>

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>

struct TrueSleep
{
  static void sleep_for(std::chrono::milliseconds duration)
  {
    std::this_thread::sleep_for(duration);
  }
};

struct SpinLoop
{
  static void sleep_for(std::chrono::milliseconds duration)
  {
    std::chrono::steady_clock clock;
    auto start = clock.now();
    auto end = start + duration;

    while (clock.now() < end)
    {
      std::this_thread::yield();
    }
  }
};

template <typename SleepImpl>
void sleep_with_many_workers(
  picobench::state& s, size_t worker_count, size_t num_sleeps)
{
  std::atomic<bool> stop_signal{false};

  for (auto i = 0; i < num_sleeps; ++i)
  {
    ccf::tasks::add_task(ccf::tasks::make_basic_task(
      []() { SleepImpl::sleep_for(std::chrono::milliseconds(1)); }));
  }

  ccf::tasks::add_task(
    ccf::tasks::make_basic_task([&]() { stop_signal.store(true); }));

  s.start_timer();
  flush_all_tasks(stop_signal, worker_count);
  s.stop_timer();
}

template <typename SleepImpl, size_t num_threads>
static void benchmark_sleeps(picobench::state& s)
{
  sleep_with_many_workers<SleepImpl>(s, num_threads, s.iterations());
}

namespace
{
  const std::vector<int> num_sleeps{100, 1000};

  auto threads_1 = benchmark_sleeps<TrueSleep, 1>;
  auto threads_2 = benchmark_sleeps<TrueSleep, 2>;
  auto threads_3 = benchmark_sleeps<TrueSleep, 3>;
  auto threads_4 = benchmark_sleeps<TrueSleep, 4>;
  auto threads_5 = benchmark_sleeps<TrueSleep, 5>;
  auto threads_6 = benchmark_sleeps<TrueSleep, 6>;
  auto threads_7 = benchmark_sleeps<TrueSleep, 7>;
  auto threads_8 = benchmark_sleeps<TrueSleep, 8>;

  PICOBENCH_SUITE("sleeps");
  PICOBENCH(threads_1).iterations(num_sleeps).baseline();
  PICOBENCH(threads_2).iterations(num_sleeps);
  PICOBENCH(threads_3).iterations(num_sleeps);
  PICOBENCH(threads_4).iterations(num_sleeps);
  PICOBENCH(threads_5).iterations(num_sleeps);
  PICOBENCH(threads_6).iterations(num_sleeps);
  PICOBENCH(threads_7).iterations(num_sleeps);
  PICOBENCH(threads_8).iterations(num_sleeps);

  auto threads_1_spin = benchmark_sleeps<SpinLoop, 1>;
  auto threads_2_spin = benchmark_sleeps<SpinLoop, 2>;
  auto threads_3_spin = benchmark_sleeps<SpinLoop, 3>;
  auto threads_4_spin = benchmark_sleeps<SpinLoop, 4>;
  auto threads_5_spin = benchmark_sleeps<SpinLoop, 5>;
  auto threads_6_spin = benchmark_sleeps<SpinLoop, 6>;
  auto threads_7_spin = benchmark_sleeps<SpinLoop, 7>;
  auto threads_8_spin = benchmark_sleeps<SpinLoop, 8>;

  PICOBENCH_SUITE("spins");
  PICOBENCH(threads_1_spin).iterations(num_sleeps).baseline();
  PICOBENCH(threads_2_spin).iterations(num_sleeps);
  PICOBENCH(threads_3_spin).iterations(num_sleeps);
  PICOBENCH(threads_4_spin).iterations(num_sleeps);
  PICOBENCH(threads_5_spin).iterations(num_sleeps);
  PICOBENCH(threads_6_spin).iterations(num_sleeps);
  PICOBENCH(threads_7_spin).iterations(num_sleeps);
  PICOBENCH(threads_8_spin).iterations(num_sleeps);
}
