// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "../key_pair.h"

#include <picobench/picobench.hpp>

using namespace std;

static const string lorem_ipsum =
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

template <size_t NBytes>
vector<uint8_t> make_contents()
{
  vector<uint8_t> contents(NBytes);
  size_t written = 0;
  while (written < NBytes)
  {
    const auto write_size = min(lorem_ipsum.size(), NBytes - written);
    memcpy(contents.data() + written, lorem_ipsum.data(), write_size);
    written += write_size;
  }
  return contents;
}

template <tls::CurveImpl Curve, size_t NContents>
static void benchmark_sign(picobench::state& s)
{
  auto kp = tls::make_key_pair(Curve);
  const auto contents = make_contents<NContents>();

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

template <tls::CurveImpl Curve, size_t NContents>
static void benchmark_verify(picobench::state& s)
{
  auto kp = tls::make_key_pair(Curve);
  const auto contents = make_contents<NContents>();

  auto signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = tls::make_public_key(
    public_key, Curve == tls::CurveImpl::secp256k1_bitcoin);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto verified = kp->verify(contents, signature);
    do_not_optimize(verified);
    clobber_memory();
  }
  s.stop_timer();
}

template <tls::CurveImpl Curve, size_t NContents>
static void benchmark_hash(picobench::state& s)
{
  auto kp = tls::make_key_pair(Curve);
  const auto contents = make_contents<NContents>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    std::vector<uint8_t> hash;
    tls::do_hash(
      *kp->get_raw_context(), contents.data(), contents.size(), hash);
    do_not_optimize(hash);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {1};

using namespace tls;

#define PICO_SUFFIX(CURVE) \
  iterations(sizes).samples(10).baseline( \
    CURVE == CurveImpl::service_identity_curve_choice)

PICOBENCH_SUITE("sign");
namespace
{
  auto sign_384_1byte = benchmark_sign<CurveImpl::secp384r1, 1>;
  PICOBENCH(sign_384_1byte).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto sign_25519_1byte = benchmark_sign<CurveImpl::ed25519, 1>;
  PICOBENCH(sign_25519_1byte).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto sign_256k1_mbed_1byte = benchmark_sign<CurveImpl::secp256k1_mbedtls, 1>;
  PICOBENCH(sign_256k1_mbed_1byte).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto sign_256k1_bitc_1byte = benchmark_sign<CurveImpl::secp256k1_bitcoin, 1>;
  PICOBENCH(sign_256k1_bitc_1byte).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);

  auto sign_384_1k = benchmark_sign<CurveImpl::secp384r1, 1024>;
  PICOBENCH(sign_384_1k).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto sign_25519_1k = benchmark_sign<CurveImpl::ed25519, 1024>;
  PICOBENCH(sign_25519_1k).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto sign_256k1_mbed_1k = benchmark_sign<CurveImpl::secp256k1_mbedtls, 1024>;
  PICOBENCH(sign_256k1_mbed_1k).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto sign_256k1_bitc_1k = benchmark_sign<CurveImpl::secp256k1_bitcoin, 1024>;
  PICOBENCH(sign_256k1_bitc_1k).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);

  auto sign_384_100k = benchmark_sign<CurveImpl::secp384r1, 102400>;
  PICOBENCH(sign_384_100k).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto sign_25519_100k = benchmark_sign<CurveImpl::ed25519, 102400>;
  PICOBENCH(sign_25519_100k).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto sign_256k1_mbed_100k =
    benchmark_sign<CurveImpl::secp256k1_mbedtls, 102400>;
  PICOBENCH(sign_256k1_mbed_100k).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto sign_256k1_bitc_100k =
    benchmark_sign<CurveImpl::secp256k1_bitcoin, 102400>;
  PICOBENCH(sign_256k1_bitc_100k).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);
}

PICOBENCH_SUITE("verify");
namespace
{
  auto verify_384_1byte = benchmark_verify<CurveImpl::secp384r1, 1>;
  PICOBENCH(verify_384_1byte).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto verify_25519_1byte = benchmark_verify<CurveImpl::ed25519, 1>;
  PICOBENCH(verify_25519_1byte).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto verify_256k1_mbed_1byte =
    benchmark_verify<CurveImpl::secp256k1_mbedtls, 1>;
  PICOBENCH(verify_256k1_mbed_1byte).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto verify_256k1_bitc_1byte =
    benchmark_verify<CurveImpl::secp256k1_bitcoin, 1>;
  PICOBENCH(verify_256k1_bitc_1byte).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);

  auto verify_384_1k = benchmark_verify<CurveImpl::secp384r1, 1024>;
  PICOBENCH(verify_384_1k).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto verify_25519_1k = benchmark_verify<CurveImpl::ed25519, 1024>;
  PICOBENCH(verify_25519_1k).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto verify_256k1_mbed_1k =
    benchmark_verify<CurveImpl::secp256k1_mbedtls, 1024>;
  PICOBENCH(verify_256k1_mbed_1k).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto verify_256k1_bitc_1k =
    benchmark_verify<CurveImpl::secp256k1_bitcoin, 1024>;
  PICOBENCH(verify_256k1_bitc_1k).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);

  auto verify_384_100k = benchmark_verify<CurveImpl::secp384r1, 102400>;
  PICOBENCH(verify_384_100k).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto verify_25519_100k = benchmark_verify<CurveImpl::ed25519, 102400>;
  PICOBENCH(verify_25519_100k).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto verify_256k1_mbed_100k =
    benchmark_verify<CurveImpl::secp256k1_mbedtls, 102400>;
  PICOBENCH(verify_256k1_mbed_100k).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto verify_256k1_bitc_100k =
    benchmark_verify<CurveImpl::secp256k1_bitcoin, 102400>;
  PICOBENCH(verify_256k1_bitc_100k).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);
}

PICOBENCH_SUITE("hash");
namespace
{
  auto hash_384_1byte = benchmark_hash<CurveImpl::secp384r1, 1>;
  PICOBENCH(hash_384_1byte).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto hash_25519_1byte = benchmark_hash<CurveImpl::ed25519, 1>;
  PICOBENCH(hash_25519_1byte).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto hash_256k1_mbed_1byte = benchmark_hash<CurveImpl::secp256k1_mbedtls, 1>;
  PICOBENCH(hash_256k1_mbed_1byte).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto hash_256k1_bitc_1byte = benchmark_hash<CurveImpl::secp256k1_bitcoin, 1>;
  PICOBENCH(hash_256k1_bitc_1byte).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);

  auto hash_384_1k = benchmark_hash<CurveImpl::secp384r1, 1024>;
  PICOBENCH(hash_384_1k).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto hash_25519_1k = benchmark_hash<CurveImpl::ed25519, 1024>;
  PICOBENCH(hash_25519_1k).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto hash_256k1_mbed_1k = benchmark_hash<CurveImpl::secp256k1_mbedtls, 1024>;
  PICOBENCH(hash_256k1_mbed_1k).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto hash_256k1_bitc_1k = benchmark_hash<CurveImpl::secp256k1_bitcoin, 1024>;
  PICOBENCH(hash_256k1_bitc_1k).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);

  auto hash_384_100k = benchmark_hash<CurveImpl::secp384r1, 102400>;
  PICOBENCH(hash_384_100k).PICO_SUFFIX(CurveImpl::secp384r1);
#ifdef MOD_MBEDTLS
  auto hash_25519_100k = benchmark_hash<CurveImpl::ed25519, 102400>;
  PICOBENCH(hash_25519_100k).PICO_SUFFIX(CurveImpl::ed25519);
#endif
  auto hash_256k1_mbed_100k =
    benchmark_hash<CurveImpl::secp256k1_mbedtls, 102400>;
  PICOBENCH(hash_256k1_mbed_100k).PICO_SUFFIX(CurveImpl::secp256k1_mbedtls);
  auto hash_256k1_bitc_100k =
    benchmark_hash<CurveImpl::secp256k1_bitcoin, 102400>;
  PICOBENCH(hash_256k1_bitc_100k).PICO_SUFFIX(CurveImpl::secp256k1_bitcoin);
}