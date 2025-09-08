// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT
#include "../history.h"

#define FMT_HEADER_ONLY

#include <algorithm>
#include <fmt/format.h>
#include <picobench/picobench.hpp>
#include <random>

using namespace std;

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
  std::random_device r;

  for (size_t i = 0; i < s.iterations(); ++i)
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
  std::random_device r;

  for (size_t i = 0; i < s.iterations(); ++i)
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
  std::random_device r;

  for (size_t i = 0; i < s.iterations(); ++i)
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
  std::random_device r;

  for (size_t i = 0; i < s.iterations(); ++i)
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
  std::random_device r;

  for (size_t i = 0; i < s.iterations(); ++i)
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
  std::random_device r;

  for (size_t i = 0; i < s.iterations(); ++i)
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
PICOBENCH(append_retract).iterations(sizes).samples(10).baseline();
PICOBENCH_SUITE("append_flush");
PICOBENCH(append_flush).iterations(sizes).samples(10).baseline();
PICOBENCH_SUITE("append_get_proof_verify");
PICOBENCH(append_get_proof_verify).iterations(sizes).samples(10).baseline();
PICOBENCH_SUITE("append_get_proof_verify_v");
PICOBENCH(append_get_proof_verify_v).iterations(sizes).samples(10).baseline();
PICOBENCH_SUITE("serialise_deserialise");
PICOBENCH(serialise_deserialise).iterations(sizes).samples(10).baseline();
// Checks the size of serialised tree, timing results are irrelevant here
// and since we run a single sample probably not that accurate anyway
PICOBENCH_SUITE("serialised_size");
PICOBENCH(serialised_size)
  .iterations({1, 2, 10, 100, 1000, 10000})
  .samples(1)
  .baseline();

int main(int argc, char* argv[])
{
  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  auto ret = runner.run();
  return ret;
}