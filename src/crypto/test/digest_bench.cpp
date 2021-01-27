// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/hash.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

enum HashImpl
{
  mbedtls,
#ifdef HAVE_OPENSSL
  openssl
#endif
};

template <HashImpl IMPL>
static void sha256_bench(picobench::state& s)
{
  std::vector<uint8_t> v(s.iterations());
  for (size_t i = 0; i < v.size(); ++i)
  {
    v.data()[i] = rand();
  }

  crypto::Sha256Hash h;

  s.start_timer();
  for (size_t i = 0; i < 10; ++i)
  {
    if constexpr (IMPL == HashImpl::mbedtls)
    {
      crypto::Sha256Hash::mbedtls_sha256(v, h.h.data());
    }
#ifdef HAVE_OPENSSL
    else if constexpr (IMPL == HashImpl::openssl)
    {
      crypto::Sha256Hash::openssl_sha256(v, h.h.data());
    }
#endif
  }
  s.stop_timer();
}

const std::vector<int> hash_sizes = {2 << 6, 2 << 8, 2 << 12, 2 << 16, 2 << 18};

PICOBENCH_SUITE("SHA-256");

auto mbedtls_digest_sha256 = sha256_bench<HashImpl::mbedtls>;
PICOBENCH(mbedtls_digest_sha256).iterations(hash_sizes).baseline();

#ifdef HAVE_OPENSSL
auto openssl_digest_sha256 = sha256_bench<HashImpl::openssl>;
PICOBENCH(openssl_digest_sha256).iterations(hash_sizes).baseline();
#endif