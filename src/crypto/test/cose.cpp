// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/cose.h"

#include "ccf/ds/hex.h"
#include "crypto/openssl/cose_verifier.h"
#include "node/cose_common.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <limits>
#include <string>
#include <vector>

// Hardcoded test vectors signed with pycose / Python cryptography (P-384).

static const auto pub_key_der = ccf::ds::from_hex(
  "3076301006072a8648ce3d020106052b81040022036200040c"
  "b505681147a976cc1fcd0326e9fd76bcbf4ebd3530070406bf"
  "6406501d26966ab947806afd24c02ae70bbc6b7405bf199a0e"
  "c26b3eee7b487dad66af87fe1669a24d8057f387035180de09"
  "5b72731a12fffccc6881abe1190e74abf25143ff");

static const std::vector<uint8_t> detached_payload = {
  'p', 'a', 'y', 'l', 'o', 'a', 'd'};
// CBOR: [1, [2, 3]]
static const auto nested_payload = ccf::ds::from_hex("8201820203");

// COSE_Sign1 with detached payload (cose_sign_ledger)
static const auto envelope_detached = ccf::ds::from_hex(
  "d2845830a501382204436b696419018b020fa3061a6553f100"
  "01636973730263737562666363662e7631a164747869646332"
  "2e31a0f6586080120aea6f4df8a233aac943c9ec53d5257a78"
  "17523f41c52e4ea814552d32755a2c3f0dbe6f70144ed30d93"
  "cf5577b3742e258d1269b7c827bf93501f068f990940fb51b7"
  "8ee9b29486e5245502cfe021983e065354a4bbaa82c9fec55c"
  "0a41");

// COSE_Sign1 with embedded flat payload (cose_sign_endorsement)
static const auto envelope_flat = ccf::ds::from_hex(
  "d2845829a30138220fa1061a6553f100666363662e7631a170"
  "65706f63682e73746172742e7478696463322e31a047706179"
  "6c6f616458609bd6fbeac88aaa877c2462863aea5f3da8b8e1"
  "14c499da2262704263635e9e7e8b3c8eb578289e574c5e4f0a"
  "26648b43031b6bb29feea3c5f0da9eaab47e8e3d3e94f75743"
  "e0b08de5d05149a6a1c1822fe9956c3edff0dcf80079fbb803"
  "ac14");

// COSE_Sign1 with embedded CBOR payload (cose_sign_endorsement)
static const auto envelope_nested = ccf::ds::from_hex(
  "d2845829a30138220fa1061a6553f100666363662e7631a170"
  "65706f63682e73746172742e7478696463322e31a045820182"
  "02035860c9417b04245e35d3d9226886bc01c515f7a5269a46"
  "58a637cce9581e9ff01e27e12021727412c15f72aa388eb068"
  "c73a5da3db8190fc4bd052b1c2174ea82b1aea1224097e8eee"
  "c8345675ebac854778f7f2434f653c7dea937b4104ab6b72ed");

struct TestEnvelope
{
  std::vector<uint8_t> envelope;
  std::vector<uint8_t> payload;
  bool detached;
};

static std::vector<TestEnvelope> test_envelopes()
{
  return {
    {envelope_detached, detached_payload, true},
    {envelope_flat, detached_payload, false},
    {envelope_nested, nested_payload, false},
  };
}

static const std::vector<int64_t> keys = {
  42, std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()};

static const std::vector<ccf::cose::edit::pos::Type> positions = {
  ccf::cose::edit::pos::AtKey{42},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<int64_t>::min()},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<int64_t>::max()},
  ccf::cose::edit::pos::InArray{}};

const std::vector<uint8_t> value = {1, 2, 3, 4};

static void verify_envelope(
  const std::vector<uint8_t>& envelope,
  const std::vector<uint8_t>& payload,
  bool detached)
{
  auto verifier = ccf::crypto::make_cose_verifier_from_key(pub_key_der);
  if (detached)
  {
    REQUIRE(verifier->verify_detached(envelope, payload));
  }
  else
  {
    std::span<uint8_t> authned_content;
    REQUIRE(verifier->verify(envelope, authned_content));
    std::vector<uint8_t> payload_copy(
      authned_content.begin(), authned_content.end());
    REQUIRE(payload == payload_copy);
  }
}

TEST_CASE("Verification and payload invariant")
{
  for (auto& [envelope, payload, detached] : test_envelopes())
  {
    verify_envelope(envelope, payload, detached);

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto edited = ccf::cose::edit::set_unprotected_header(envelope, desc);

        verify_envelope(edited, payload, detached);
      }
    }

    {
      auto edited = ccf::cose::edit::set_unprotected_header(
        envelope, ccf::cose::edit::desc::Empty{});
      verify_envelope(edited, payload, detached);
    }
  }
}

TEST_CASE("Idempotence")
{
  for (auto& [envelope, payload, detached] : test_envelopes())
  {
    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto set_once = ccf::cose::edit::set_unprotected_header(envelope, desc);

        auto set_twice =
          ccf::cose::edit::set_unprotected_header(set_once, desc);
        REQUIRE(set_once == set_twice);
      }
    }

    {
      auto set_empty = ccf::cose::edit::set_unprotected_header(
        envelope, ccf::cose::edit::desc::Empty{});
      auto set_twice_empty = ccf::cose::edit::set_unprotected_header(
        set_empty, ccf::cose::edit::desc::Empty{});

      REQUIRE(set_empty == set_twice_empty);
    }
  }
}

TEST_CASE("Check unprotected header")
{
  for (auto& [envelope, payload, detached] : test_envelopes())
  {
    using namespace ccf::cbor;

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto edited = ccf::cose::edit::set_unprotected_header(envelope, desc);

        auto parsed = parse(edited);
        const auto& uhdr =
          parsed->tag_at(ccf::cbor::tag::COSE_SIGN_1)->array_at(1);

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
      auto edited = ccf::cose::edit::set_unprotected_header(
        envelope, ccf::cose::edit::desc::Empty{});

      auto parsed = parse(edited);
      const auto& uhdr =
        parsed->tag_at(ccf::cbor::tag::COSE_SIGN_1)->array_at(1);

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