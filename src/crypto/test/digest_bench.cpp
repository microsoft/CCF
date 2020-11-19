// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/hash.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

static void evercrypt_sha256(picobench::state& s)
{
  std::vector<uint8_t> v(s.iterations());
  for (size_t i = 0; i < v.size(); ++i)
  {
    v.data()[i] = rand();
  }

  crypto::Sha256Hash h;

  s.start_timer();
  for (size_t i = 0; i < 1000; ++i)
  {
    crypto::Sha256Hash::evercrypt_sha256(v, h.h.data());
  }
  s.stop_timer();
}

static void mbedtls_sha256(picobench::state& s)
{
  std::vector<uint8_t> v(s.iterations());
  for (size_t i = 0; i < v.size(); ++i)
  {
    v.data()[i] = rand();
  }

  crypto::Sha256Hash h;

  s.start_timer();
  for (size_t i = 0; i < 1000; ++i)
  {
    crypto::Sha256Hash::mbedtls_sha256(v, h.h.data());
  }
  s.stop_timer();
}

const std::vector<int> hash_sizes = {2 << 6, 2 << 8, 2 << 12, 2 << 16, 2 << 18};

PICOBENCH_SUITE("SHA-256");

PICOBENCH(evercrypt_sha256).iterations(hash_sizes).baseline();
PICOBENCH(mbedtls_sha256).iterations(hash_sizes).baseline();