// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/cose.h"

#include "ccf/ds/hex.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/cose_verifier.h"
#include "node/cose_common.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

static const std::vector<int64_t> keys = {
  42, std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()};

static const std::vector<ccf::cose::edit::pos::Type> positions = {
  ccf::cose::edit::pos::AtKey{42},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<int64_t>::min()},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<int64_t>::max()},
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
  ccf::crypto::ECKeyPair_OpenSSL kp;
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
        using namespace ccf::cbor;

        std::vector<Value> arr;
        arr.push_back(make_signed(1));

        std::vector<Value> inner;
        inner.push_back(make_signed(2));
        inner.push_back(make_signed(3));

        arr.push_back(make_array(std::move(inner)));

        payload = serialize(make_array(std::move(arr)));
      }
      break;
    }
  }

  std::vector<uint8_t> make_cose_sign1()
  {
    using namespace ccf::cbor;

    std::vector<MapItem> phdr;
    phdr.emplace_back(make_signed(300), make_bytes(value));
    phdr.emplace_back(make_signed(301), make_signed(34));
    auto phdr_map = make_map(std::move(phdr));

    return ccf::crypto::cose_sign1(kp, phdr_map, payload, detached_payload);
  };

  void verify(const std::vector<uint8_t>& cose_sign1)
  {
    auto verifier =
      ccf::crypto::make_cose_verifier_from_key(kp.public_key_pem());
    if (detached_payload)
    {
      REQUIRE(verifier->verify_detached(cose_sign1, payload));
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
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto csp_set = ccf::cose::edit::set_unprotected_header(csp, desc);

        signer.verify(csp_set);
      }
    }

    {
      auto csp_set_empty = ccf::cose::edit::set_unprotected_header(
        csp, ccf::cose::edit::desc::Empty{});
      signer.verify(csp_set_empty);
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
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto csp_set_once = ccf::cose::edit::set_unprotected_header(csp, desc);

        auto csp_set_twice =
          ccf::cose::edit::set_unprotected_header(csp_set_once, desc);
        REQUIRE(csp_set_once == csp_set_twice);
      }
    }

    {
      auto csp_set_empty = ccf::cose::edit::set_unprotected_header(
        csp, ccf::cose::edit::desc::Empty{});
      auto csp_set_twice_empty = ccf::cose::edit::set_unprotected_header(
        csp_set_empty, ccf::cose::edit::desc::Empty{});

      REQUIRE(csp_set_empty == csp_set_twice_empty);
    }
  }
}

TEST_CASE("Check unprotected header")
{
  for (auto type :
       {PayloadType::Detached, PayloadType::Flat, PayloadType::NestedCBOR})
  {
    Signer signer(type);
    auto csp = signer.make_cose_sign1();

    using namespace ccf::cbor;

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto csp_set = ccf::cose::edit::set_unprotected_header(csp, desc);

        auto edited = parse(csp_set);
        const auto& uhdr =
          edited->tag_at(ccf::cbor::tag::COSE_SIGN_1)->array_at(1);

        std::vector<MapItem> ref;
        if (std::holds_alternative<ccf::cose::edit::pos::InArray>(position))
        {
          std::vector<Value> items{make_bytes(value)};

          ref.emplace_back(make_signed(key), make_array(std::move(items)));
        }
        else if (std::holds_alternative<ccf::cose::edit::pos::AtKey>(position))
        {
          auto subkey = std::get<ccf::cose::edit::pos::AtKey>(position).key;

          std::vector<Value> items{make_bytes(value)};
          std::vector<MapItem> inner_map{
            {make_signed(subkey), make_array(std::move(items))}};

          ref.emplace_back(make_signed(key), make_map(std::move(inner_map)));
        }
        auto ref_map = make_map(std::move(ref));

        REQUIRE_EQ(to_string(ref_map), to_string(uhdr));
      }
    }

    {
      auto csp_set_empty = ccf::cose::edit::set_unprotected_header(
        csp, ccf::cose::edit::desc::Empty{});

      auto edited = parse(csp_set_empty);
      const auto& uhdr =
        edited->tag_at(ccf::cbor::tag::COSE_SIGN_1)->array_at(1);

      auto ref_map = make_map({});

      REQUIRE_EQ(to_string(ref_map), to_string(uhdr));
    }
  }
}

TEST_CASE("Decode CCF COSE receipt")
{
  const std::string receipt_hex =
    "d284588ca50138220458403464393230653531646339303636373336653433333738636131"
    "34323863656165306435343335326634306535316232306564633863366237633536316430"
    "3519018b020fa3061a692875730173736572766963652e6578616d706c652e636f6d02706c"
    "65646765722e7369676e6174757265666363662e7631a1647478696464322e3137a119018c"
    "a1208158b7a201835820e2a97fad0c69119d6e216158b762b19277a579d7a89047d98aa37f"
    "152f194a92784863653a322e31363a38633765646230386135323963613237326166623062"
    "31653664613939306233636137336665313064336535663462356633663231613561346638"
    "37663637635820000000000000000000000000000000000000000000000000000000000000"
    "0000028182f55820d774c9dfeec96478a0797f8ce3d78464767833d052fb78d72b2b8eeda5"
    "21215af658604568ff2c93350fa181bf02186b26d3f04728a61fd2ef2c9388a55268ed8bf7"
    "88a6bd06bfa195c78676bebeef5560a87980e8dd13725a87ef0b00ac0b78ff07ab7eb4646a"
    "4a54b421456d14e90b7dea1f0b32044bf93116d85ef0834f493681d5";

  const auto receipt_bytes = ccf::ds::from_hex(receipt_hex);

  auto receipt =
    ccf::cose::decode_ccf_receipt(receipt_bytes, /*recompute_root*/ true);

  REQUIRE(receipt.phdr.alg == -35);
  REQUIRE(
    ccf::ds::to_hex(receipt.phdr.kid) ==
    "34643932306535316463393036363733366534333337386361313432386365616530643534"
    "333532663430653531623230656463386336623763353631643035");
  REQUIRE(receipt.phdr.cwt.iat.value() == 1764259187);
  REQUIRE(receipt.phdr.cwt.iss == "service.example.com");
  REQUIRE(receipt.phdr.cwt.sub == "ledger.signature");
  REQUIRE(receipt.phdr.ccf.txid == "2.17");
  REQUIRE(receipt.phdr.vds == 2);

  REQUIRE(
    ccf::ds::to_hex(receipt.merkle_root) ==
    "209f5aefb0f45d7647c917337044c44a1b848fe833fa2869d016bea797d79a9e");
}