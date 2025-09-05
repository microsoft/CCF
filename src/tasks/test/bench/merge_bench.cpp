// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "./flush_all_tasks.h"
#include "./merge_sort.h"

#include <random>

#define PICOBENCH_DONT_BIND_TO_ONE_CORE
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>

static inline std::span<int> get_merge_sort_data(size_t n)
{
  static std::vector<int> data;
  static std::random_device rd;
  static std::mt19937 g(rd());

  while (data.size() < n)
  {
    data.emplace_back(rand());
  }

  auto begin = data.begin();
  auto end = begin + n;
  std::shuffle(begin, end, g);

  return {begin, end};
}

void do_merge_sort(picobench::state& s, size_t worker_count, size_t data_size)
{
  auto ns = get_merge_sort_data(data_size);
  if (std::is_sorted(ns.begin(), ns.end()))
  {
    throw std::logic_error("Initial data already sorted");
  }

  std::atomic<bool> stop_signal{false};

  ccf::tasks::add_task(
    std::make_shared<MergeSortTask>(ns.begin(), ns.end(), stop_signal));

  s.start_timer();
  flush_all_tasks(stop_signal, worker_count);
  s.stop_timer();

  if (!std::is_sorted(ns.begin(), ns.end()))
  {
    throw std::logic_error("Final data not sorted");
  }
}

template <size_t num_threads>
static void benchmark_mergesort(picobench::state& s)
{
  do_merge_sort(s, num_threads, s.iterations());
}

namespace
{
  const std::vector<int> data_sizes{1'000, 1'000'000};

  auto threads_1 = benchmark_mergesort<1>;
  auto threads_2 = benchmark_mergesort<2>;
  auto threads_3 = benchmark_mergesort<3>;
  auto threads_4 = benchmark_mergesort<4>;
  auto threads_5 = benchmark_mergesort<5>;
  auto threads_6 = benchmark_mergesort<6>;
  auto threads_7 = benchmark_mergesort<7>;
  auto threads_8 = benchmark_mergesort<8>;

  PICOBENCH_SUITE("merge sort");
  PICOBENCH(threads_1).iterations(data_sizes).baseline();
  PICOBENCH(threads_2).iterations(data_sizes);
  PICOBENCH(threads_3).iterations(data_sizes);
  PICOBENCH(threads_4).iterations(data_sizes);
  PICOBENCH(threads_5).iterations(data_sizes);
  PICOBENCH(threads_6).iterations(data_sizes);
  PICOBENCH(threads_7).iterations(data_sizes);
  PICOBENCH(threads_8).iterations(data_sizes);
}
