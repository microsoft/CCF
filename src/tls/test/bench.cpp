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

static constexpr auto curve = tls::CurveImpl::default_curve_choice;

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <tls::CurveImpl Curve, size_t Repeats>
static void benchmark_sign(picobench::state& s)
{
  auto kp = tls::make_key_pair(Curve);
  vector<uint8_t> contents(contents_.size() * Repeats);
  for (decltype(Repeats) i = 0; i < Repeats; i++)
  {
    copy(contents_.begin(), contents_.end(), back_inserter(contents));
  }

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto signature = kp->sign(contents);
    do_not_optimize(signature);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t Repeats>
static void benchmark_verify(picobench::state& s)
{
  auto kp = tls::make_key_pair(curve);
  vector<uint8_t> contents(contents_.size() * Repeats);
  for (decltype(Repeats) i = 0; i < Repeats; i++)
  {
    copy(contents_.begin(), contents_.end(), back_inserter(contents));
  }
  auto signature = kp->sign(contents);
  auto public_key = kp->public_key();
  auto pubk = tls::make_public_key(curve, public_key);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto verified = pubk->verify(contents, signature);
    do_not_optimize(verified);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t Repeats>
static void benchmark_hash(picobench::state& s)
{
  auto kp = tls::make_key_pair(curve);
  vector<uint8_t> contents(contents_.size() * Repeats);
  for (decltype(Repeats) i = 0; i < Repeats; i++)
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

const std::vector<int> sizes = {8, 16};

using namespace tls;

PICOBENCH_SUITE("sign");
auto sign_384_1 = benchmark_sign<CurveImpl::secp384r1, 1>;
PICOBENCH(sign_384_1)
  .iterations(sizes)
  .samples(10)
  .baseline(CurveImpl::secp384r1 == CurveImpl::default_curve_choice);
auto sign_384_100 = benchmark_sign<CurveImpl::secp384r1, 100>;
PICOBENCH(sign_384_100).iterations(sizes).samples(10);

auto sign_25519_1 = benchmark_sign<CurveImpl::curve25519, 1>;
PICOBENCH(sign_25519_1)
  .iterations(sizes)
  .samples(10)
  .baseline(CurveImpl::curve25519 == CurveImpl::default_curve_choice);
auto sign_25519_100 = benchmark_sign<CurveImpl::curve25519, 100>;
PICOBENCH(sign_25519_100).iterations(sizes).samples(10);

auto sign_256k1_mbed_1 = benchmark_sign<CurveImpl::secp256k1_mbedtls, 1>;
PICOBENCH(sign_256k1_mbed_1)
  .iterations(sizes)
  .samples(10)
  .baseline(CurveImpl::secp256k1_mbedtls == CurveImpl::default_curve_choice);
auto sign_256k1_mbed_100 = benchmark_sign<CurveImpl::secp256k1_mbedtls, 100>;
PICOBENCH(sign_256k1_mbed_100).iterations(sizes).samples(10);

auto sign_256k1_bitc_1 = benchmark_sign<CurveImpl::secp256k1_bitcoin, 1>;
PICOBENCH(sign_256k1_bitc_1)
  .iterations(sizes)
  .samples(10)
  .baseline(CurveImpl::secp256k1_bitcoin == CurveImpl::default_curve_choice);
auto sign_256k1_bitc_100 = benchmark_sign<CurveImpl::secp256k1_bitcoin, 100>;
PICOBENCH(sign_256k1_bitc_100).iterations(sizes).samples(10);

PICOBENCH_SUITE("verify");
PICOBENCH(benchmark_verify<1>).iterations(sizes).samples(10).baseline();
PICOBENCH(benchmark_verify<10>).iterations(sizes).samples(10);
PICOBENCH(benchmark_verify<100>).iterations(sizes).samples(10);

PICOBENCH_SUITE("hash");
PICOBENCH(benchmark_hash<1>).iterations(sizes).samples(10).baseline();
PICOBENCH(benchmark_hash<10>).iterations(sizes).samples(10);
PICOBENCH(benchmark_hash<100>).iterations(sizes).samples(10);