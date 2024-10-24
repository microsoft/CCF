// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/cose.h"

#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/cose_verifier.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

static const std::vector<ssize_t> keys = {
  42, std::numeric_limits<ssize_t>::min(), std::numeric_limits<ssize_t>::max()};

static const std::vector<ccf::cose::edit::pos::Type> positions = {
  ccf::cose::edit::pos::AtKey{42},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<ssize_t>::min()},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<ssize_t>::max()},
  ccf::cose::edit::pos::InArray{}};

const std::vector<uint8_t> value = {1, 2, 3, 4};

enum class PayloadType
{
  Detached,
  Flat,
  NestedCBOR // Useful to test the payload transfer
};

struct Signer
{
  ccf::crypto::KeyPair_OpenSSL kp;
  std::vector<uint8_t> payload;
  bool detached_payload = false;

  Signer(PayloadType type) : kp(ccf::crypto::CurveID::SECP384R1)
  {
    switch (type)
    {
      case PayloadType::Detached:
        detached_payload = true;
        payload = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
        break;
      case PayloadType::Flat:
        payload = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
        break;
      case PayloadType::NestedCBOR:
      {
        payload.resize(1024);
        QCBOREncodeContext ctx;
        QCBOREncode_Init(&ctx, {payload.data(), payload.size()});
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddInt64(&ctx, 1);
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddInt64(&ctx, 2);
        QCBOREncode_AddInt64(&ctx, 3);
        QCBOREncode_CloseArray(&ctx);
        QCBOREncode_CloseArray(&ctx);
        UsefulBufC result;
        QCBOREncode_Finish(&ctx, &result);
        payload.resize(result.len);
        payload.shrink_to_fit();
      }
      break;
    }
  }

  std::vector<uint8_t> make_cose_sign1()
  {
    const auto pheaders = {
      ccf::crypto::cose_params_int_bytes(300, value),
      ccf::crypto::cose_params_int_int(301, 34)};

    return ccf::crypto::cose_sign1(kp, pheaders, payload, false);
  };

  void verify(const std::vector<uint8_t>& cose_sign1)
  {
    auto verifier =
      ccf::crypto::make_cose_verifier_from_key(kp.public_key_pem());
    if (detached_payload)
    {
      verifier->verify_detached(cose_sign1, payload);
    }
    else
    {
      std::span<uint8_t> payload_;
      REQUIRE(verifier->verify(cose_sign1, payload_));
      std::vector<uint8_t> payload_copy(payload_.begin(), payload_.end());
      REQUIRE(payload == payload_copy);
    }
  };
};

TEST_CASE("Verification and payload invariant")
{
  for (auto type :
       {PayloadType::Detached, PayloadType::Flat, PayloadType::NestedCBOR})
  {
    Signer signer(type);
    auto csp = signer.make_cose_sign1();
    signer.verify(csp);

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        auto csp_set =
          ccf::cose::edit::set_unprotected_header(csp, key, position, value);

        signer.verify(csp_set);
      }
    }
  }
}

TEST_CASE("Idempotence")
{
  for (auto type :
       {PayloadType::Detached, PayloadType::Flat, PayloadType::NestedCBOR})
  {
    Signer signer(type);
    auto csp = signer.make_cose_sign1();

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        auto csp_set_once =
          ccf::cose::edit::set_unprotected_header(csp, key, position, value);

        auto csp_set_twice = ccf::cose::edit::set_unprotected_header(
          csp_set_once, key, position, value);
        REQUIRE(csp_set_once == csp_set_twice);
      }
    }
  }
}