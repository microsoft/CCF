// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <crypto/hash.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string.h>
#include <tls/curve.h>
#include <tls/entropy.h>
#include <tls/key_pair.h>
#include <tls/mbedtls_wrappers.h>

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

using namespace tls;
using namespace crypto;

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <typename T, CurveID CURVE>
static void signature_bench(picobench::state& s)
{
  std::vector<Sha256Hash> hashes(s.iterations());
  for (size_t i = 0; i < s.iterations(); i++)
  {
    for (size_t i = 0; i < Sha256Hash::SIZE; ++i)
    {
      hashes.back().h[i] = rand();
    }
  }

  T kp(CURVE);

  s.start_timer();
  for (auto& hash : hashes)
  {
    auto sig = kp.sign_hash(hash.h.data(), hash.SIZE);
    do_not_optimize(sig);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> num_hashes = {1, 25};

PICOBENCH_SUITE("Signatures");

auto secp384r1_mbedtls = signature_bench<KeyPair_mbedTLS, CurveID::SECP384R1>;
PICOBENCH(secp384r1_mbedtls).iterations(num_hashes).baseline();
auto secp256k1_mbedtls = signature_bench<KeyPair_mbedTLS, CurveID::SECP256K1>;
PICOBENCH(secp256k1_mbedtls).iterations(num_hashes).baseline();
auto secp256r1_mbedtls = signature_bench<KeyPair_mbedTLS, CurveID::SECP256R1>;
PICOBENCH(secp256r1_mbedtls).iterations(num_hashes).baseline();

auto secp256k1_bitcoin = signature_bench<KeyPair_k1Bitcoin, CurveID::SECP256K1>;
PICOBENCH(secp256k1_bitcoin).iterations(num_hashes).baseline();

auto secp384r1_openssl = signature_bench<KeyPair_OpenSSL, CurveID::SECP384R1>;
PICOBENCH(secp384r1_openssl).iterations(num_hashes).baseline();
auto secp256k1_openssl = signature_bench<KeyPair_OpenSSL, CurveID::SECP256K1>;
PICOBENCH(secp256k1_openssl).iterations(num_hashes).baseline();
auto secp256r1_openssl = signature_bench<KeyPair_OpenSSL, CurveID::SECP256R1>;
PICOBENCH(secp256r1_openssl).iterations(num_hashes).baseline();
