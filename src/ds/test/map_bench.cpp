// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "../champ_map.h"
#include "../rb_map.h"

#include <map>
#include <picobench/picobench.hpp>
#include <type_traits>
#include <unordered_map>

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
    if constexpr (
      std::is_same_v<M, champ::Map<K, V>> || std::is_same_v<M, rb::Map<K, V>>)
    {
      map = map.put(i, v);
    }
    else
    {
      map[i] = v;
    }
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
    if constexpr (
      std::is_same_v<M, champ::Map<K, V>> || std::is_same_v<M, rb::Map<K, V>>)
    {
      auto res = map.put(size, v);
      do_not_optimize(res);
    }
    else
    {
      map[size] = v;
    }
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
    if constexpr (
      std::is_same_v<M, champ::Map<K, V>> || std::is_same_v<M, rb::Map<K, V>>)
    {
      auto res = map.get(0);
      do_not_optimize(res);
    }
    else
    {
      auto res = map.at(0);
      do_not_optimize(res);
    }
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
static void benchmark_remove(picobench::state& s)
{
  size_t size = s.iterations();
  auto map = gen_map<M>(size);
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    if constexpr (
      std::is_same_v<M, champ::Map<K, V>> || std::is_same_v<M, rb::Map<K, V>>)
    {
      auto res = map.remove(0);
      do_not_optimize(res);
    }
    else
    {
      auto res = map.erase(0);
      do_not_optimize(res);
    }
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
    if constexpr (
      std::is_same_v<M, champ::Map<K, V>> || std::is_same_v<M, rb::Map<K, V>>)
    {
      map.foreach([&count, map](const auto& key, const auto& value) {
        count++;
        return true;
      });
      clobber_memory();
    }
    else
    {
      for (auto const& e : map)
      {
        count++;
      }
      clobber_memory();
    }
  }
  s.stop_timer();
}

const std::vector<int> sizes = {32, 32 << 2, 32 << 4, 32 << 6, 32 << 8};

PICOBENCH_SUITE("put");
auto bench_rb_map_put = benchmark_put<rb::Map<K, V>>;
PICOBENCH(bench_rb_map_put).iterations(sizes).baseline();
auto bench_champ_map_put = benchmark_put<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_put).iterations(sizes);

// std
auto bench_std_map_put = benchmark_put<std::map<K, V>>;
PICOBENCH(bench_std_map_put).iterations(sizes);
auto bench_std_unord_map_put = benchmark_put<std::unordered_map<K, V>>;
PICOBENCH(bench_std_unord_map_put).iterations(sizes);

PICOBENCH_SUITE("get");
auto bench_rb_map_get = benchmark_get<rb::Map<K, V>>;
PICOBENCH(bench_rb_map_get).iterations(sizes).baseline();
auto bench_champ_map_get = benchmark_get<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_get).iterations(sizes);

// std
auto bench_std_map_get = benchmark_get<std::map<K, V>>;
PICOBENCH(bench_std_map_get).iterations(sizes);
auto bench_std_unord_map_get = benchmark_get<std::unordered_map<K, V>>;
PICOBENCH(bench_std_unord_map_get).iterations(sizes);

PICOBENCH_SUITE("getp");
auto bench_rb_map_getp = benchmark_getp<rb::Map<K, V>>;
PICOBENCH(bench_rb_map_getp).iterations(sizes).baseline();
auto bench_champ_map_getp = benchmark_getp<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_getp).iterations(sizes);

PICOBENCH_SUITE("foreach");
auto bench_rb_map_foreach = benchmark_foreach<rb::Map<K, V>>;
PICOBENCH(bench_rb_map_foreach).iterations(sizes).baseline();
auto bench_champ_map_foreach = benchmark_foreach<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_foreach).iterations(sizes);

// std
auto bench_std_map_foreach = benchmark_foreach<std::map<K, V>>;
PICOBENCH(bench_std_map_foreach).iterations(sizes);
auto bench_unord_map_foreach = benchmark_foreach<std::unordered_map<K, V>>;
PICOBENCH(bench_unord_map_foreach).iterations(sizes);

PICOBENCH_SUITE("remove");
auto bench_rb_map_remove = benchmark_remove<rb::Map<K, V>>;
PICOBENCH(bench_rb_map_remove).iterations(sizes).baseline();
auto bench_champ_map_remove = benchmark_remove<champ::Map<K, V>>;
PICOBENCH(bench_champ_map_remove).iterations(sizes);

// std
auto bench_std_map_remove = benchmark_remove<std::map<K, V>>;
PICOBENCH(bench_std_map_remove).iterations(sizes);
auto bench_unord_map_remove = benchmark_remove<std::unordered_map<K, V>>;
PICOBENCH(bench_unord_map_remove).iterations(sizes);
