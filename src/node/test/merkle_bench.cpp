// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT
#include "../history.h"

#define FMT_HEADER_ONLY

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <fmt/format.h>
#include <iostream>
#include <picobench/picobench.hpp>
#include <random>
#include <string_view>

using namespace std;

// Merkle tree operations do not depend on leaf hashes being unpredictable, so
// synthetic leaves come from a PRNG rather than from per-byte hardware entropy,
// which is slow and host-dependent. A seed is drawn once per run (or read from
// RNG_SEED) and printed, and each sample re-seeds its own generator with it, so
// a sample's inputs do not depend on picobench's randomised execution order.
static uint32_t rng_seed = 0;

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

static void append_retract(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<ccf::crypto::Sha256Hash> hashes;
  std::mt19937 r(rng_seed);

  for (int i = 0; i < s.iterations(); ++i)
  {
    ccf::crypto::Sha256Hash h;
    for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
      h.h[j] = r();

    hashes.emplace_back(h);
  }

  size_t index = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    t.append(hashes[index++]);

    if (index > 0 && index % 1000 == 0)
    {
      t.retract(index - 1000);
    }

    // do_not_optimize();
    clobber_memory();
  }
  s.stop_timer();
}

static void append_flush(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<ccf::crypto::Sha256Hash> hashes;
  std::mt19937 r(rng_seed);

  for (int i = 0; i < s.iterations(); ++i)
  {
    ccf::crypto::Sha256Hash h;
    for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
      h.h[j] = r();

    hashes.emplace_back(h);
  }

  size_t index = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    t.append(hashes[index++]);
    if (index > 0 && index % 1000 == 0)
      t.flush(index - 1000);

    // do_not_optimize();
    clobber_memory();
  }
  s.stop_timer();
}

static void append_get_proof_verify(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<ccf::crypto::Sha256Hash> hashes;
  std::mt19937 r(rng_seed);

  for (int i = 0; i < s.iterations(); ++i)
  {
    ccf::crypto::Sha256Hash h;
    for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
      h.h[j] = r();

    hashes.emplace_back(h);
  }

  size_t index = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    t.append(hashes[index++]);

    auto p = t.get_proof(index);
    if (!t.verify(p))
      throw std::runtime_error("Bad path");

    // do_not_optimize();
    clobber_memory();
  }
  s.stop_timer();
}

static void append_get_proof_verify_v(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<ccf::crypto::Sha256Hash> hashes;
  std::mt19937 r(rng_seed);

  for (int i = 0; i < s.iterations(); ++i)
  {
    ccf::crypto::Sha256Hash h;
    for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
      h.h[j] = r();

    hashes.emplace_back(h);
  }

  size_t index = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    t.append(hashes[index++]);

    auto v = t.get_proof(index).to_v();
    ccf::Proof proof(v);
    if (!t.verify(proof))
      throw std::runtime_error("Bad path");

    // do_not_optimize();
    clobber_memory();
  }
  s.stop_timer();
}

static void serialise_deserialise(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  std::mt19937 r(rng_seed);

  for (int i = 0; i < s.iterations(); ++i)
  {
    ccf::crypto::Sha256Hash h;
    for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
      h.h[j] = r();
    t.append(h);
  }

  s.start_timer();
  auto buf = t.serialise();
  auto ds = ccf::MerkleTreeHistory(buf);
  s.stop_timer();
}

static void serialised_size(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  std::mt19937 r(rng_seed);

  for (int i = 0; i < s.iterations(); ++i)
  {
    ccf::crypto::Sha256Hash h;
    for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
      h.h[j] = r();
    t.append(h);
  }

  s.start_timer();
  auto buf = t.serialise();
  s.stop_timer();
  auto bph = ((float)buf.size()) / s.iterations();
  std::cout << fmt::format(
                 "mt_serialize n={} : {} bytes, {} bytes/hash, {}% overhead",
                 s.iterations(),
                 buf.size(),
                 bph,
                 (bph - ccf::crypto::Sha256Hash::SIZE) * 100 /
                   ccf::crypto::Sha256Hash::SIZE)
            << std::endl;
}

const std::vector<int> sizes = {1000, 10000};

PICOBENCH_SUITE("append_retract");
PICOBENCH(append_retract).iterations(sizes).baseline();
PICOBENCH_SUITE("append_flush");
PICOBENCH(append_flush).iterations(sizes).baseline();
PICOBENCH_SUITE("append_get_proof_verify");
PICOBENCH(append_get_proof_verify).iterations(sizes).baseline();
PICOBENCH_SUITE("append_get_proof_verify_v");
PICOBENCH(append_get_proof_verify_v).iterations(sizes).baseline();
PICOBENCH_SUITE("serialise_deserialise");
PICOBENCH(serialise_deserialise).iterations(sizes).baseline();
// Checks the size of serialised tree, timing results are irrelevant here
// and since we run a single sample probably not that accurate anyway
PICOBENCH_SUITE("serialised_size");
PICOBENCH(serialised_size)
  .iterations({1, 2, 10, 100, 1000, 10000})
  .samples(1)
  .baseline();

int main(int argc, char* argv[])
{
  const char* env_seed = std::getenv("RNG_SEED");
  if (env_seed != nullptr && *env_seed != '\0')
  {
    const std::string_view seed_str(env_seed);
    const auto* seed_end = seed_str.data() + seed_str.size();
    const auto [ptr, ec] = std::from_chars(seed_str.data(), seed_end, rng_seed);
    if (ec != std::errc() || ptr != seed_end)
    {
      std::cerr << fmt::format(
                     "RNG_SEED must be an unsigned 32-bit integer, not '{}'",
                     seed_str)
                << std::endl;
      return 1;
    }
  }
  else
  {
    rng_seed = std::random_device{}();
  }
  std::cerr << fmt::format("RNG seed: {} (set RNG_SEED to reproduce)", rng_seed)
            << std::endl;

  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  auto ret = runner.run();
  return ret;
}