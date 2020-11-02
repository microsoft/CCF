// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "crypto/hash.h"
#include "crypto/symmetric_key.h"
#include "tls/base64.h"
#include "tls/entropy.h"

#include <doctest/doctest.h>
#include <mbedtls/pem.h>
#include <vector>

using namespace crypto;
using namespace std;

static const vector<uint8_t>& getRawKey()
{
  static const vector<uint8_t> v(16, '$');
  return v;
}

TEST_CASE("ExtendedIv0")
{
  KeyAesGcm k(getRawKey());
  // setup plain text
  unsigned char rawP[100];
  memset(rawP, 'x', sizeof(rawP));
  Buffer p{rawP, sizeof(rawP)};
  // test large IV
  GcmHeader<1234> h;
  k.encrypt(h.get_iv(), p, nullb, p.p, h.tag);

  KeyAesGcm k2(getRawKey());
  REQUIRE(k2.decrypt(h.get_iv(), h.tag, p, nullb, p.p));
}

TEST_CASE("SHA256 short consistency test")
{
  std::vector<uint8_t> data = {'a', 'b', 'c', 'd', '\n'};
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256(data, h1.h.data());
  crypto::Sha256Hash::mbedtls_sha256(data, h2.h.data());
  REQUIRE(h1 == h2);
}

TEST_CASE("SHA256 %32 consistency test")
{
  std::vector<uint8_t> data(32);
  for (unsigned i = 0; i < 32; i++)
    std::iota(data.begin(), data.end(), 0);
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256(data, h1.h.data());
  crypto::Sha256Hash::mbedtls_sha256(data, h2.h.data());
  REQUIRE(h1 == h2);

  CSha256Hash ch;
  ch.update_hash(data);
  crypto::Sha256Hash h3 = ch.finalize();
  REQUIRE(h1 == h3);
}

TEST_CASE("SHA256 long consistency test")
{
  std::vector<uint8_t> data(512);
  std::iota(data.begin(), data.end(), 0);
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256(data, h1.h.data());
  crypto::Sha256Hash::mbedtls_sha256(data, h2.h.data());
  REQUIRE(h1 == h2);
}

TEST_CASE("Sha256 interesting size consistency test")
{
  std::vector<uint8_t> full_data(8192);
  std::iota(full_data.begin(), full_data.end(), 0);

  for (size_t size : {0u,    1u,    4u,    10u,   63u,   64u,   65u,   127u,
                      128u,  129u,  150u,  200u,  500u,  1000u, 1023u, 1024u,
                      1025u, 2000u, 5000u, 8190u, 8191u, 8192u})
  {
    INFO(fmt::format("Hashing {} bytes", size));
    auto data =
      std::vector<uint8_t>(full_data.begin(), full_data.begin() + size);
    crypto::Sha256Hash h1, h2;
    crypto::Sha256Hash::evercrypt_sha256(data, h1.h.data());
    crypto::Sha256Hash::mbedtls_sha256(data, h2.h.data());
    CHECK(h1 == h2);
  }
}

TEST_CASE("EverCrypt SHA256 no-collision check")
{
  std::vector<uint8_t> data1 = {'a', 'b', 'c', '\n'};
  std::vector<uint8_t> data2 = {'a', 'b', 'd', '\n'};
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256(data1, h1.h.data());
  crypto::Sha256Hash::evercrypt_sha256(data2, h2.h.data());
  REQUIRE(h1 != h2);
}