// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "flush_all_jobs.h"
#include "tasks/basic_task.h"

#define PICOBENCH_DONT_BIND_TO_ONE_CORE
#include <picobench/picobench.hpp>

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>

void sleep_with_many_workers(
  picobench::state& s, size_t worker_count, size_t num_sleeps)
{
  std::atomic<bool> stop_signal{false};

  for (auto i = 0; i < num_sleeps; ++i)
  {
    ccf::tasks::add_task(ccf::tasks::make_basic_task(
      []() { std::this_thread::sleep_for(std::chrono::milliseconds(1)); }));
  }

  ccf::tasks::add_task(
    ccf::tasks::make_basic_task([&]() { stop_signal.store(true); }));

  s.start_timer();
  flush_all_jobs(stop_signal, worker_count);
  s.stop_timer();
}

template <size_t num_threads>
static void benchmark_sleeps(picobench::state& s)
{
  sleep_with_many_workers(s, num_threads, s.iterations());
}

namespace
{
  const std::vector<int> num_sleeps{100, 1000};

  auto threads_1 = benchmark_sleeps<1>;
  auto threads_2 = benchmark_sleeps<2>;
  auto threads_3 = benchmark_sleeps<3>;
  auto threads_4 = benchmark_sleeps<4>;
  auto threads_5 = benchmark_sleeps<5>;
  auto threads_6 = benchmark_sleeps<6>;
  auto threads_7 = benchmark_sleeps<7>;
  auto threads_8 = benchmark_sleeps<8>;

  PICOBENCH_SUITE("sleeps");
  PICOBENCH(threads_1).iterations(num_sleeps).baseline();
  PICOBENCH(threads_2).iterations(num_sleeps);
  PICOBENCH(threads_3).iterations(num_sleeps);
  PICOBENCH(threads_4).iterations(num_sleeps);
  PICOBENCH(threads_5).iterations(num_sleeps);
  PICOBENCH(threads_6).iterations(num_sleeps);
  PICOBENCH(threads_7).iterations(num_sleeps);
  PICOBENCH(threads_8).iterations(num_sleeps);
}
