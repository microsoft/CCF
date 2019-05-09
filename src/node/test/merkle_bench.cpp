// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT
#include "../history.h"

#include <algorithm>
#include <picobench/picobench.hpp>
#include <random>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

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

static void append(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<crypto::Sha256Hash> hashes;

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    crypto::Sha256Hash h;
    vector<uint8_t> hv(crypto::Sha256Hash::SIZE, 0u);
    generate(hv.begin(), hv.end(), rand);
    h.mbedtls_sha256({hv}, h.h);
    hashes.emplace_back(h);
  }

  size_t index = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    t.append(hashes[index++]);
    // do_not_optimize();
    clobber_memory();
  }
  s.stop_timer();
}

static void append_retract(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<crypto::Sha256Hash> hashes;

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    crypto::Sha256Hash h;
    vector<uint8_t> hv(crypto::Sha256Hash::SIZE, 0u);
    generate(hv.begin(), hv.end(), rand);
    h.mbedtls_sha256({hv}, h.h);
    hashes.emplace_back(h);
  }

  size_t index = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    t.append(hashes[index++]);
    if (index > 0 && index % 1000 == 0)
      t.retract(index - 1000);

    // do_not_optimize();
    clobber_memory();
  }
  s.stop_timer();
}

static void append_flush(picobench::state& s)
{
  ccf::MerkleTreeHistory t;
  vector<crypto::Sha256Hash> hashes;

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    crypto::Sha256Hash h;
    vector<uint8_t> hv(crypto::Sha256Hash::SIZE, 0u);
    generate(hv.begin(), hv.end(), rand);
    h.mbedtls_sha256({hv}, h.h);
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

const std::vector<int> sizes = {10000, 100000};

PICOBENCH_SUITE("append");
PICOBENCH(append).iterations(sizes).samples(10).baseline();
PICOBENCH_SUITE("append_retract");
PICOBENCH(append_retract).iterations(sizes).samples(10).baseline();
PICOBENCH_SUITE("append_flush");
PICOBENCH(append_flush).iterations(sizes).samples(10).baseline();

// We need an explicit main to initialize kremlib and EverCrypt
int main(int argc, char* argv[])
{
  ::EverCrypt_AutoConfig2_init();
  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}