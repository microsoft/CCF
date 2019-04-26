// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../hash.h"
#include "../symmkey.h"

#include <doctest/doctest.h>
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
  k.encrypt(h.getIv(), p, nullb, p.p, h.tag);

  KeyAesGcm k2(getRawKey());
  REQUIRE(k2.decrypt(h.getIv(), h.tag, p, nullb, p.p));
}

TEST_CASE("SHA256 short consistency test")
{
  std::vector<uint8_t> data = {'a', 'b', 'c', '\n'};
  crypto::Sha256Hash h1, h2, h3;
  crypto::Sha256Hash::evercrypt_sha256({data}, h1.h);
  crypto::Sha256Hash::mbedtls_sha256({data}, h2.h);
  crypto::Sha256Hash::hacl_sha256({data}, h3.h);
  REQUIRE(h1 == h2);
  REQUIRE(h1 == h3);
}

TEST_CASE("SHA256 %32 consistency test")
{
  std::vector<uint8_t> data(32);
  for (unsigned i = 0; i < 32; i++)
    data[i] = i;
  crypto::Sha256Hash h1, h2, h3;
  crypto::Sha256Hash::evercrypt_sha256({data}, h1.h);
  crypto::Sha256Hash::mbedtls_sha256({data}, h2.h);
  crypto::Sha256Hash::hacl_sha256({data}, h3.h);
  REQUIRE(h1 == h2);
  REQUIRE(h1 == h3);
}

TEST_CASE("SHA256 long consistency test")
{
  std::vector<uint8_t> data(512);
  for (unsigned i = 0; i < 512; i++)
    data[i] = i;
  crypto::Sha256Hash h1, h2, h3;
  crypto::Sha256Hash::evercrypt_sha256({data}, h1.h);
  crypto::Sha256Hash::mbedtls_sha256({data}, h2.h);
  crypto::Sha256Hash::hacl_sha256({data}, h3.h);
  REQUIRE(h1 == h2);
  REQUIRE(h1 == h3);
}

TEST_CASE("EverCrypt SHA256 no-collision check")
{
  std::vector<uint8_t> data1 = {'a', 'b', 'c', '\n'};
  std::vector<uint8_t> data2 = {'a', 'b', 'd', '\n'};
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256({data1}, h1.h);
  crypto::Sha256Hash::evercrypt_sha256({data2}, h2.h);
  REQUIRE(h1 != h2);
}