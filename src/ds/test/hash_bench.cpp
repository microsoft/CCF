// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/byte_vector.h"
#include "ccf/ds/hash.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

template <typename T>
static void hash(picobench::state& s)
{
  T v(s.iterations());
  auto* d = v.data();
  for (size_t i = 0; i < v.size(); ++i)
  {
    d[i] = rand();
  }

  std::hash<T> hasher;

  s.start_timer();
  for (size_t i = 0; i < 1000; ++i)
  {
    volatile auto n = hasher(v);
    s.stop_timer();
  }
}

const std::vector<int> hash_sizes = {1, 8, 64, 1024, 16536};

PICOBENCH_SUITE("hash");
auto hash_vec = hash<std::vector<uint8_t>>;
PICOBENCH(hash_vec).iterations(hash_sizes).baseline();
auto hash_small_vec_16 = hash<llvm_vecsmall::SmallVector<uint8_t, 16>>;
PICOBENCH(hash_small_vec_16).iterations(hash_sizes).baseline();
auto hash_small_vec_128 = hash<llvm_vecsmall::SmallVector<uint8_t, 128>>;
PICOBENCH(hash_small_vec_128).iterations(hash_sizes).baseline();
