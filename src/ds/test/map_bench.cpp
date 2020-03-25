// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "../champ_map.h"
#include "../rb_map.h"

#include <picobench/picobench.hpp>

using namespace std;

using K = uint64_t;
using V = std::vector<uint64_t>;

static size_t val_size = 32;

static V gen_val(size_t size)
{
  V v;

  for (uint64_t i = 0; i < size; ++i)
  {
    v.push_back(i);
  }

  return v;
}

template <class M>
static const M gen_map(size_t size)
{
  auto v = gen_val(val_size);

  M map;
  for (uint64_t i = 0; i < size; ++i)
  {
    map = map.put(i, v);
  }
  return map;
}

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <class M>
static void benchmark_put(picobench::state& s)
{
  size_t size = s.iterations();
  auto v = gen_val(val_size);
  auto map = gen_map<M>(size);
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto res = map.put(size, v);
    do_not_optimize(res);
    clobber_memory();
  }
  s.stop_timer();
}

template <class M>
static void benchmark_get(picobench::state& s)
{
  size_t size = s.iterations();
  auto map = gen_map<M>(size);
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto res = map.get(0);
    do_not_optimize(res);
    clobber_memory();
  }
  s.stop_timer();
}

template <class M>
static void benchmark_getp(picobench::state& s)
{
  size_t size = s.iterations();
  auto map = gen_map<M>(size);
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto res = map.getp(0);
    do_not_optimize(res);
    clobber_memory();
  }
  s.stop_timer();
}

template <class M>
static void benchmark_foreach(picobench::state& s)
{
  size_t size = s.iterations();
  auto map = gen_map<M>(size);
  size_t count = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    map.foreach([&count, map](const auto& key, const auto& value) {
      count++;
      return true;
    });
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {32, 32 << 2, 32 << 4, 32 << 6, 32 << 8};

PICOBENCH_SUITE("put");
auto bench_rb_map_put = benchmark_put<RBMap<K, V>>;
PICOBENCH(bench_rb_map_put).iterations(sizes).samples(10).baseline();
auto bench_champ_map_put = benchmark_put<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_put).iterations(sizes).samples(10);

PICOBENCH_SUITE("get");
auto bench_rb_map_get = benchmark_get<RBMap<K, V>>;
PICOBENCH(bench_rb_map_get).iterations(sizes).samples(10).baseline();
auto bench_rb_map_getp = benchmark_getp<RBMap<K, V>>;
PICOBENCH(bench_rb_map_getp).iterations(sizes).samples(10);
auto bench_champ_map_get = benchmark_get<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_get).iterations(sizes).samples(10);
auto bench_champ_map_getp = benchmark_getp<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_getp).iterations(sizes).samples(10);

const std::vector<int> for_sizes = {32 << 4, 32 << 5, 32 << 6};

PICOBENCH_SUITE("foreach");
auto bench_rb_map_foreach = benchmark_foreach<RBMap<K, V>>;
PICOBENCH(bench_rb_map_foreach).iterations(for_sizes).samples(10).baseline();
auto bench_champ_map_foreach = benchmark_foreach<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_foreach).iterations(for_sizes).samples(10);
