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

TEST_CASE("Bitcoin hash")
{
  BitcoinHashProvider hp1;
  OpenSSLHashProvider hp2;

  std::vector<uint8_t> msg(32);
  for (size_t i = 0; i < msg.size(); i++)
    msg[i] = i;

  auto r1 = hp1.Hash(msg.data(), msg.size(), MDType::SHA256);
  auto r2 = hp2.Hash(msg.data(), msg.size(), MDType::SHA256);

  CHECK(r1 == r2);
}