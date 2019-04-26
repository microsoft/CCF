// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "../keypair.h"
#include <picobench/picobench.hpp>

using namespace std;

static constexpr size_t SHA256_BYTES = 256 / 8;
static const string contents_ = 
                       "Lorem ipsum dolor sit amet, consectetur adipiscing "
                       "elit, sed do eiusmod tempor incididunt ut labore et"
                       " dolore magna aliqua. Ut enim ad minim veniam, quis"
                       " nostrud exercitation ullamco laboris nisi ut "
                       "aliquip ex ea commodo consequat. Duis aute irure "
                       "dolor in reprehenderit in voluptate velit esse "
                       "cillum dolore eu fugiat nulla pariatur. Excepteur "
                       "sint occaecat cupidatat non proident, sunt in culpa "
                       "qui officia deserunt mollit anim id est laborum.";

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <size_t C>
static void benchmark_sign(picobench::state& s)
{
  tls::KeyPair kp;
  vector<uint8_t> contents(contents_.size() * C);
  for(decltype(C) i = 0; i < C; i++)
  {
      copy(contents_.begin(), contents_.end(), back_inserter(contents));
  }

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto signature = kp.sign(contents);
    do_not_optimize(signature);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t C>
static void benchmark_verify(picobench::state& s)
{
  tls::KeyPair kp;
  vector<uint8_t> contents(contents_.size() * C);
  for(decltype(C) i = 0; i < C; i++)
  {
      copy(contents_.begin(), contents_.end(), back_inserter(contents));
  }
  auto signature = kp.sign(contents);
  auto public_key = kp.public_key();
  tls::PublicKey pubk(public_key);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto verified = pubk.verify(contents, signature);
    do_not_optimize(verified);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t C>
static void benchmark_hash(picobench::state& s)
{
  tls::KeyPair kp;
  vector<uint8_t> contents(contents_.size() * C);
  for(decltype(C) i = 0; i < C; i++)
  {
      copy(contents_.begin(), contents_.end(), back_inserter(contents));
  }

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    uint8_t hash[SHA256_BYTES];
    mbedtls_sha256_ret(contents.data(), contents.size(), hash, 0);
    do_not_optimize(hash);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {8, 16, 32};

PICOBENCH_SUITE("sign");
PICOBENCH(benchmark_sign<1>).iterations(sizes).samples(10).baseline();
PICOBENCH(benchmark_sign<10>).iterations(sizes).samples(10);
PICOBENCH(benchmark_sign<100>).iterations(sizes).samples(10);

PICOBENCH_SUITE("verify");
PICOBENCH(benchmark_verify<1>).iterations(sizes).samples(10).baseline();
PICOBENCH(benchmark_verify<10>).iterations(sizes).samples(10);
PICOBENCH(benchmark_verify<100>).iterations(sizes).samples(10);

PICOBENCH_SUITE("hash");
PICOBENCH(benchmark_hash<1>).iterations(sizes).samples(10).baseline();
PICOBENCH(benchmark_hash<10>).iterations(sizes).samples(10);
PICOBENCH(benchmark_hash<100>).iterations(sizes).samples(10);