// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/cose.h"

#include "ccf/crypto/cose_key.h"
#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "crypto/cbor_helpers.h"
#include "crypto/certs.h"
#include "crypto/cose.h"
#include "crypto/openssl/cose_verifier.h"
#include "crypto/openssl/ec_key_pair.h"
#include "crypto/test/cbor_printer.h"
#include "node/cose_common.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <doctest/doctest.h>
#include <exception>
#include <limits>
#include <stdexcept>
#include <string>
#include <tav/cbor.hpp>
#include <tuple>
#include <utility>
#include <variant>
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

// COSE_Sign1 with detached payload (sign_ledger)
static const auto envelope_detached = ccf::ds::from_hex(
  "d2845830a501382204436b696419018b020fa3061a6553f100"
  "01636973730263737562666363662e7631a164747869646332"
  "2e31a0f6586080120aea6f4df8a233aac943c9ec53d5257a78"
  "17523f41c52e4ea814552d32755a2c3f0dbe6f70144ed30d93"
  "cf5577b3742e258d1269b7c827bf93501f068f990940fb51b7"
  "8ee9b29486e5245502cfe021983e065354a4bbaa82c9fec55c"
  "0a41");

// COSE_Sign1 with embedded flat payload (sign_endorsement)
static const auto envelope_flat = ccf::ds::from_hex(
  "d2845829a30138220fa1061a6553f100666363662e7631a170"
  "65706f63682e73746172742e7478696463322e31a047706179"
  "6c6f616458609bd6fbeac88aaa877c2462863aea5f3da8b8e1"
  "14c499da2262704263635e9e7e8b3c8eb578289e574c5e4f0a"
  "26648b43031b6bb29feea3c5f0da9eaab47e8e3d3e94f75743"
  "e0b08de5d05149a6a1c1822fe9956c3edff0dcf80079fbb803"
  "ac14");

// COSE_Sign1 with embedded CBOR payload (sign_endorsement)
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

TEST_CASE("COSE Sign1 TBS encoding")
{
  // {alg: ES256}, with label 1 encoded as 18 01 rather than 01.
  // The TBS must preserve these header bytes, not canonicalize them.
  const auto noncanonical_phdr = ccf::ds::from_hex("a1180126");
  const auto payload = ccf::ds::from_hex("0001ff");
  CHECK(
    ccf::cose::make_cose_sign1_tbs(noncanonical_phdr, payload) ==
    ccf::ds::from_hex("846a5369676e61747572653144a118012640430001ff"));
  CHECK(
    ccf::cose::make_cose_sign1_tbs({}, {}) ==
    ccf::ds::from_hex("846a5369676e617475726531404040"));
}

TEST_CASE("COSE Sign1 envelope encoding")
{
  // Non-minimal alg label (18 01): the envelope must retain exactly
  // the protected header bytes that were signed.
  const auto noncanonical_phdr = ccf::ds::from_hex("a1180126");
  const auto payload = ccf::ds::from_hex("0001ff");
  const auto signature = ccf::ds::from_hex("aabbcc");
  CHECK(
    ccf::cose::make_cose_sign1_envelope(
      noncanonical_phdr, payload, signature, false) ==
    ccf::ds::from_hex("d28444a1180126a0430001ff43aabbcc"));
  CHECK(
    ccf::cose::make_cose_sign1_envelope(
      noncanonical_phdr, payload, signature, true) ==
    ccf::ds::from_hex("d28444a1180126a0f643aabbcc"));
  CHECK(
    ccf::cose::make_cose_sign1_envelope({}, {}, {}, false) ==
    ccf::ds::from_hex("d28440a04040"));
  CHECK(
    ccf::cose::make_cose_sign1_envelope({}, {}, {}, true) ==
    ccf::ds::from_hex("d28440a0f640"));
}

TEST_CASE("COSE Sign1 signing with empty payloads")
{
  using namespace tav::cbor;
  const auto key =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  const auto verifier =
    ccf::crypto::make_cose_verifier_from_key(key->public_key_der());

  for (const bool detached : {false, true})
  {
    CAPTURE(detached);
    const auto envelope = detached ?
      ccf::cose::sign_ledger(*key, "kid", 1700000000, "iss", "sub", "2.1", {}) :
      ccf::cose::sign_endorsement(*key, 1700000000, "2.1", {}, {}, {});
    const auto fields =
      nondet_parse(envelope).tag_at(ccf::cbor::tag::COSE_SIGN_1);
    REQUIRE(fields.size() == 4);
    CHECK(fields.array_at(1).det_serialize() == ccf::ds::from_hex("a0"));
    if (detached)
    {
      CHECK(fields.array_at(2).as_simple() == SimpleValue::Null);
      CHECK(verifier->verify_detached(envelope, {}));
    }
    else
    {
      CHECK(fields.array_at(2).as_bytes().empty());
      std::span<uint8_t> authenticated;
      REQUIRE(verifier->verify(envelope, authenticated));
      CHECK(authenticated.empty());
    }
  }
}

TEST_CASE("COSE Sign1 signing failures")
{
  using ccf::crypto::CurveID;

  struct FailingKey : ccf::crypto::ECKeyPair_OpenSSL
  {
    using ccf::crypto::ECKeyPair_OpenSSL::ECKeyPair_OpenSSL;
    CurveID curve = CurveID::SECP384R1;
    std::exception_ptr error;
    std::vector<uint8_t> signature;

    CurveID get_curve_id() const override
    {
      return curve;
    }

    std::vector<uint8_t> sign(
      std::span<const uint8_t>, ccf::crypto::MDType) const override
    {
      if (error)
      {
        std::rethrow_exception(error);
      }
      return signature;
    }
  };

  FailingKey key(ccf::crypto::CurveID::SECP384R1);
  CHECK_THROWS_WITH_AS(
    ccf::cose::sign_endorsement(key, 1700000000, "2.1", {}, {}, {}),
    "COSE signing returned an empty signature",
    std::runtime_error);

  key.signature = {0xff};
  CHECK_THROWS_AS(
    ccf::cose::sign_endorsement(key, 1700000000, "2.1", {}, {}, {}),
    std::runtime_error);

  for (const auto& error :
       {std::make_exception_ptr(std::runtime_error("signing failed")),
        std::make_exception_ptr(std::logic_error("signing failed"))})
  {
    key.error = error;
    CHECK_THROWS_WITH(
      ccf::cose::sign_ledger(key, "kid", 1700000000, "iss", "sub", "2.1", {}),
      "signing failed");
    CHECK_THROWS_WITH(
      ccf::cose::sign_endorsement(key, 1700000000, "2.1", {}, {}, {}),
      "signing failed");
  }

  for (const auto curve : {CurveID::NONE, CurveID::CURVE25519, CurveID::X25519})
  {
    key.curve = curve;
    CHECK_THROWS_WITH_AS(
      ccf::cose::sign_ledger(key, "kid", 1700000000, "iss", "sub", "2.1", {}),
      "Unsupported COSE signing curve",
      std::runtime_error);
    CHECK_THROWS_WITH_AS(
      ccf::cose::sign_endorsement(key, 1700000000, "2.1", {}, {}, {}),
      "Unsupported COSE signing curve",
      std::runtime_error);
  }
}

TEST_CASE("COSE signing propagates CBOR encoding failures")
{
  const auto key =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  const std::string invalid_utf8 = "\xff";
  CHECK_THROWS_AS(
    ccf::cose::sign_ledger(
      *key, "kid", 1700000000, invalid_utf8, "sub", "2.1", {}),
    tav::cbor::EncodeError);
  CHECK_THROWS_AS(
    ccf::cose::sign_endorsement(*key, 1700000000, invalid_utf8, {}, {}, {}),
    tav::cbor::EncodeError);
}

TEST_CASE("COSE ECDSA round trips and algorithm binding")
{
  using namespace tav::cbor;
  using ccf::cose::header::iana::ALG;
  using ccf::crypto::CurveID;
  struct Curve
  {
    CurveID id;
    int64_t es;
    int64_t esp;
    size_t signature_size;
  };
  constexpr std::array curves = {
    Curve{CurveID::SECP256R1, -7, -9, 64},
    Curve{CurveID::SECP384R1, -35, -51, 96},
    Curve{CurveID::SECP521R1, -36, -52, 132}};

  for (const auto& curve : curves)
  {
    CAPTURE(curve.es);
    const auto key = ccf::crypto::make_ec_key_pair(curve.id);
    const auto verifier =
      ccf::crypto::make_cose_verifier_from_key(key->public_key_der());
    const auto envelope = ccf::cose::sign_endorsement(
      *key, 1700000000, "2.1", {}, {}, detached_payload);
    const auto fields =
      nondet_parse(envelope).tag_at(ccf::cbor::tag::COSE_SIGN_1);
    const auto phdr_bytes = fields.array_at(0).as_bytes();
    const auto phdr = nondet_parse(phdr_bytes);
    const auto sig = fields.array_at(3).as_bytes();
    CHECK(phdr.map_at(make_signed(ALG)).as_signed() == curve.es);
    REQUIRE(sig.size() == curve.signature_size);
    std::span<uint8_t> authenticated;
    REQUIRE(verifier->verify(envelope, authenticated));
    CHECK(std::ranges::equal(authenticated, detached_payload));

    for (const auto& candidate : curves)
    {
      for (const auto alg : {candidate.es, candidate.esp})
      {
        CAPTURE(alg);
        CHECK(
          verifier->verify_decomposed(phdr_bytes, detached_payload, sig, alg) ==
          (candidate.id == curve.id));
      }
    }
    for (const auto alg : {0, -37})
    {
      CAPTURE(alg);
      CHECK_FALSE(
        verifier->verify_decomposed(phdr_bytes, detached_payload, sig, alg));
    }

    auto wrong_payload = detached_payload;
    wrong_payload.back() ^= 0xff;
    CHECK_FALSE(
      verifier->verify_decomposed(phdr_bytes, wrong_payload, sig, curve.es));
    CHECK_FALSE(ccf::crypto::make_cose_verifier_from_key(
                  ccf::crypto::make_ec_key_pair(curve.id)->public_key_der())
                  ->verify(envelope, authenticated));
    for (const auto size : {size_t{0}, sig.size() - 1, sig.size() + 1})
    {
      CAPTURE(size);
      std::vector<uint8_t> malformed_sig(sig.begin(), sig.end());
      malformed_sig.resize(size);
      CHECK_FALSE(verifier->verify_decomposed(
        phdr_bytes, detached_payload, malformed_sig, curve.es));
    }

    const auto esp_phdr =
      ccf::cbor::with_entry(phdr, ALG, make_signed(curve.esp)).det_serialize();
    const auto esp_tbs =
      ccf::cose::make_cose_sign1_tbs(esp_phdr, detached_payload);
    const auto esp_sig =
      ccf::crypto::ecdsa_sig_der_to_p1363(key->sign(esp_tbs), curve.id);
    const auto esp_fields =
      ccf::cbor::with_element(fields, 0, make_bytes(esp_phdr));
    const auto esp_envelope =
      make_tagged(
        ccf::cbor::tag::COSE_SIGN_1,
        ccf::cbor::with_element(esp_fields, 3, make_bytes(esp_sig)))
        .det_serialize();
    REQUIRE(verifier->verify(esp_envelope, authenticated));
    CHECK(std::ranges::equal(authenticated, detached_payload));
  }
}

TEST_CASE("COSE signing protected header bytes")
{
  // Must stay byte-identical to headers already written to existing ledgers.
  const auto key =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  const auto phdr = [](const std::vector<uint8_t>& envelope) {
    const auto bytes = tav::cbor::nondet_parse(envelope)
                         .tag_at(ccf::cbor::tag::COSE_SIGN_1)
                         .array_at(0)
                         .as_bytes();
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
  };
  CHECK(
    phdr(ccf::cose::sign_ledger(
      *key, "kid", 1700000000, "iss", "sub", "2.1", {})) ==
    ccf::ds::from_hex(
      "a501382204436b69640fa301636973730263737562061a6553f10019018b0266"
      "6363662e7631a1647478696463322e31"));
  const std::vector<uint8_t> root = {0xaa, 0xbb};
  CHECK(
    phdr(
      ccf::cose::sign_endorsement(*key, 1700000000, "2.1", "3.4", root, {})) ==
    ccf::ds::from_hex(
      "a30138220fa1061a6553f100666363662e7631a36e65706f63682e656e642e74"
      "78696463332e347065706f63682e73746172742e7478696463322e317565706f"
      "63682e656e642e6d65726b6c652e726f6f7442aabb"));
}

TEST_CASE("COSE RSA-PSS verification")
{
  using ccf::crypto::MDType;
  const auto key = ccf::crypto::make_rsa_key_pair();
  const auto issuer =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  const auto cert = ccf::crypto::create_endorsed_cert(
    key->public_key_pem(),
    "CN=rsa",
    {},
    "20200101000000Z",
    "20301231235959Z",
    issuer->private_key_pem(),
    issuer->self_sign("CN=issuer", "20200101000000Z", "20301231235959Z"));
  const std::array verifiers = {
    ccf::crypto::make_cose_verifier_from_key(key->public_key_der()),
    ccf::crypto::make_cose_verifier_from_pem_cert(cert)};
  const auto phdr = ccf::ds::from_hex("a0");
  const auto tbs = ccf::cose::make_cose_sign1_tbs(phdr, detached_payload);

  for (const auto& [alg, md, salt] :
       {std::tuple{-37, MDType::SHA256, 32},
        std::tuple{-38, MDType::SHA384, 48},
        std::tuple{-39, MDType::SHA512, 64}})
  {
    CAPTURE(alg);
    const auto sig = key->sign(tbs, md, salt);
    // RFC 8230 requires the PSS salt length to equal the hash length.
    const auto unsalted_sig = key->sign(tbs, md, 0);
    for (const auto& verifier : verifiers)
    {
      CHECK(verifier->verify_decomposed(phdr, detached_payload, sig, alg));
      CHECK_FALSE(
        verifier->verify_decomposed(phdr, detached_payload, unsalted_sig, alg));
      CHECK_FALSE(verifier->verify_decomposed(phdr, detached_payload, sig, -7));
    }
  }
}

TEST_CASE("COSE verifier returns false for malformed messages")
{
  const std::vector<uint8_t> malformed = {0xff};
  const auto verifier = ccf::crypto::make_cose_verifier_from_key(pub_key_der);
  std::span<uint8_t> authenticated;
  CHECK_FALSE(verifier->verify(malformed, authenticated));
  CHECK_FALSE(verifier->verify_detached(malformed, detached_payload));
  // COSE_Sign1 [h'', {}, true, h'']: the payload is neither a bstr nor nil
  const auto bad_payload = ccf::ds::from_hex("d28440a0f540");
  CHECK_FALSE(verifier->verify(bad_payload, authenticated));
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
    using namespace tav::cbor;

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto edited = ccf::cose::edit::set_unprotected_header(envelope, desc);

        auto parsed = nondet_parse(edited);
        const auto& uhdr =
          parsed.tag_at(ccf::cbor::tag::COSE_SIGN_1).array_at(1);

        std::vector<MapItem> ref;
        if (std::holds_alternative<ccf::cose::edit::pos::InArray>(position))
        {
          std::vector<Value> items;
          items.push_back(make_bytes(value));

          ref.emplace_back(make_signed(key), make_array(std::move(items)));
        }
        else if (std::holds_alternative<ccf::cose::edit::pos::AtKey>(position))
        {
          auto subkey = std::get<ccf::cose::edit::pos::AtKey>(position).key;

          std::vector<Value> items;
          items.push_back(make_bytes(value));
          std::vector<MapItem> inner_map;
          inner_map.emplace_back(
            make_signed(subkey), make_array(std::move(items)));

          ref.emplace_back(make_signed(key), make_map(std::move(inner_map)));
        }
        auto ref_map = make_map(std::move(ref));

        REQUIRE_EQ(
          ccf::cbor::test::to_string(ref_map),
          ccf::cbor::test::to_string(uhdr));
      }
    }

    {
      auto edited = ccf::cose::edit::set_unprotected_header(
        envelope, ccf::cose::edit::desc::Empty{});

      auto parsed = nondet_parse(edited);
      const auto& uhdr = parsed.tag_at(ccf::cbor::tag::COSE_SIGN_1).array_at(1);

      auto ref_map = make_map({});

      REQUIRE_EQ(
        ccf::cbor::test::to_string(ref_map), ccf::cbor::test::to_string(uhdr));
    }
  }
}

TEST_CASE("Detach payload")
{
  using namespace tav::cbor;

  for (auto& [envelope, payload, detached] : test_envelopes())
  {
    const auto detached_envelope = ccf::cose::edit::detach_payload(envelope);

    // Still verifies against the original payload, but no longer as an
    // envelope with an embedded payload
    verify_envelope(detached_envelope, payload, true);
    {
      auto verifier = ccf::crypto::make_cose_verifier_from_key(pub_key_der);
      std::span<uint8_t> authned_content;
      REQUIRE_FALSE(verifier->verify(detached_envelope, authned_content));
    }

    // Payload is nil, protected header and signature are preserved
    {
      const auto original =
        nondet_parse(envelope).tag_at(ccf::cbor::tag::COSE_SIGN_1);
      const auto edited =
        nondet_parse(detached_envelope).tag_at(ccf::cbor::tag::COSE_SIGN_1);
      REQUIRE(edited.size() == 4);

      const auto payload_item = edited.array_at(2);
      REQUIRE_EQ(payload_item.kind(), Kind::SIMPLE);
      REQUIRE_EQ(payload_item.as_simple(), SimpleValue::Null);

      const auto original_phdr = original.array_at(0).as_bytes();
      const auto edited_phdr = edited.array_at(0).as_bytes();
      REQUIRE(std::ranges::equal(original_phdr, edited_phdr));

      const auto original_sig = original.array_at(3).as_bytes();
      const auto edited_sig = edited.array_at(3).as_bytes();
      REQUIRE(std::ranges::equal(original_sig, edited_sig));

      REQUIRE_EQ(
        ccf::cbor::test::to_string(original.array_at(1)),
        ccf::cbor::test::to_string(edited.array_at(1)));
    }

    // Idempotent
    REQUIRE_EQ(
      ccf::cose::edit::detach_payload(detached_envelope), detached_envelope);

    // Composes with unprotected header edits
    for (const auto& position : positions)
    {
      ccf::cose::edit::desc::Value desc{position, keys.front(), value};
      const auto edited =
        ccf::cose::edit::set_unprotected_header(detached_envelope, desc);
      verify_envelope(edited, payload, true);
      REQUIRE_EQ(
        ccf::cose::edit::detach_payload(edited),
        ccf::cose::edit::detach_payload(
          ccf::cose::edit::set_unprotected_header(envelope, desc)));
    }
  }

  // Malformed inputs are rejected rather than rewritten
  {
    const std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
    REQUIRE_THROWS_AS(
      ccf::cose::edit::detach_payload(garbage), tav::cbor::DecodeError);

    // Untagged COSE_Sign1 structure
    const auto untagged = nondet_parse(envelope_flat)
                            .tag_at(ccf::cbor::tag::COSE_SIGN_1)
                            .nondet_serialize();
    REQUIRE_THROWS_AS(
      ccf::cose::edit::detach_payload(untagged), tav::cbor::DecodeError);

    // Payload which is neither a byte string nor nil
    const auto structure =
      nondet_parse(envelope_flat).tag_at(ccf::cbor::tag::COSE_SIGN_1);
    const Value with_int_payload = make_tagged(
      ccf::cbor::tag::COSE_SIGN_1,
      ccf::cbor::with_element(structure, 2, make_signed(42)));
    REQUIRE_THROWS_AS(
      ccf::cose::edit::detach_payload(with_int_payload.nondet_serialize()),
      tav::cbor::DecodeError);

    // Missing signature
    std::vector<Value> truncated;
    truncated.push_back(structure.array_at(0));
    truncated.push_back(structure.array_at(1));
    truncated.push_back(structure.array_at(2));
    const Value without_signature = make_tagged(
      ccf::cbor::tag::COSE_SIGN_1, make_array(std::move(truncated)));
    REQUIRE_THROWS_AS(
      ccf::cose::edit::detach_payload(without_signature.nondet_serialize()),
      tav::cbor::DecodeError);

    // Extra element beyond the four of COSE_Sign1 must not be silently
    // dropped, even though the first four elements are well-formed
    std::vector<Value> extended;
    for (size_t i = 0; i < structure.size(); ++i)
    {
      extended.push_back(structure.array_at(i));
    }
    extended.push_back(make_bytes(value));
    const Value with_extra_element =
      make_tagged(ccf::cbor::tag::COSE_SIGN_1, make_array(std::move(extended)));
    REQUIRE_THROWS_AS(
      ccf::cose::edit::detach_payload(with_extra_element.nondet_serialize()),
      tav::cbor::DecodeError);
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

  enum class ProofHashField
  {
    WriteSetDigest,
    ClaimsDigest,
    Sibling,
  };
  const auto with_proof_hash_size = [&](ProofHashField field, size_t size) {
    using namespace tav::cbor;

    auto receipt = nondet_parse(receipt_bytes);
    const auto& envelope = receipt.tag_at(ccf::cbor::tag::COSE_SIGN_1);
    const auto& unprotected = envelope.array_at(1);
    const auto& vdp =
      unprotected.map_at(make_signed(ccf::cose::header::iana::VDP));
    const auto& proofs =
      vdp.map_at(make_signed(ccf::cose::header::iana::INCLUSION_PROOFS));
    auto proof = nondet_parse(proofs.array_at(0).as_bytes());

    std::vector<uint8_t> replacement(size, 0x42);
    std::array<uint8_t, 1> empty_replacement{};
    const std::span<const uint8_t> replacement_span = replacement.empty() ?
      std::span<const uint8_t>(empty_replacement.data(), 0) :
      std::span<const uint8_t>(replacement);
    Value edited_proof;
    if (field == ProofHashField::Sibling)
    {
      const auto path = proof.map_at(
        make_signed(ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL));
      const auto link = path.array_at(0);
      auto edited_link =
        ccf::cbor::with_element(link, 1, make_bytes(replacement_span));
      auto edited_path =
        ccf::cbor::with_element(path, 0, std::move(edited_link));
      edited_proof = ccf::cbor::with_entry(
        proof,
        ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL,
        std::move(edited_path));
    }
    else
    {
      const auto leaf = proof.map_at(
        make_signed(ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL));
      const auto index = field == ProofHashField::WriteSetDigest ? 0 : 2;
      auto edited_leaf =
        ccf::cbor::with_element(leaf, index, make_bytes(replacement_span));
      edited_proof = ccf::cbor::with_entry(
        proof,
        ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL,
        std::move(edited_leaf));
    }

    const auto serialised_proof = edited_proof.nondet_serialize();
    auto edited_proofs =
      ccf::cbor::with_element(proofs, 0, make_bytes(serialised_proof));
    auto edited_vdp = ccf::cbor::with_entry(
      vdp, ccf::cose::header::iana::INCLUSION_PROOFS, std::move(edited_proofs));
    auto edited_unprotected = ccf::cbor::with_entry(
      unprotected, ccf::cose::header::iana::VDP, std::move(edited_vdp));
    auto edited_envelope =
      ccf::cbor::with_element(envelope, 1, std::move(edited_unprotected));
    const Value edited_receipt =
      make_tagged(ccf::cbor::tag::COSE_SIGN_1, std::move(edited_envelope));
    return edited_receipt.nondet_serialize();
  };
  const auto decode_proofs = [](const std::vector<uint8_t>& receipt_bytes) {
    auto receipt = tav::cbor::nondet_parse(receipt_bytes);
    const auto& envelope = receipt.tag_at(ccf::cbor::tag::COSE_SIGN_1);
    return ccf::cose::decode_merkle_proofs(envelope);
  };
  const auto with_decoded_proof_hash_size =
    [&](ProofHashField field, size_t size) {
      auto proof = decode_proofs(receipt_bytes).at(0);
      auto* hash = &proof.leaf.claims_digest;
      if (field == ProofHashField::WriteSetDigest)
      {
        hash = &proof.leaf.write_set_digest;
      }
      else if (field == ProofHashField::Sibling)
      {
        hash = &proof.path.at(0).second;
      }
      hash->assign(size, 0x42);
      return proof;
    };

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

  for (const auto size :
       {size_t{0}, size_t{1}, size_t{31}, size_t{32}, size_t{33}})
  {
    const auto edited = with_proof_hash_size(ProofHashField::Sibling, size);
    if (size == ccf::crypto::Sha256Hash::SIZE)
    {
      REQUIRE_NOTHROW(ccf::cose::decode_ccf_receipt(edited, true));
    }
    else
    {
      REQUIRE_THROWS_AS(decode_proofs(edited), ccf::cose::COSEDecodeError);
    }
  }

  for (const auto field :
       {ProofHashField::WriteSetDigest, ProofHashField::ClaimsDigest})
  {
    for (const auto size : {size_t{0}, size_t{31}, size_t{33}})
    {
      const auto malformed = with_proof_hash_size(field, size);
      REQUIRE_THROWS_AS(decode_proofs(malformed), ccf::cose::COSEDecodeError);
    }

    const auto valid =
      with_proof_hash_size(field, ccf::crypto::Sha256Hash::SIZE);
    REQUIRE_NOTHROW(ccf::cose::decode_ccf_receipt(valid, true));
  }

  for (const auto field :
       {ProofHashField::WriteSetDigest,
        ProofHashField::ClaimsDigest,
        ProofHashField::Sibling})
  {
    const auto malformed = with_decoded_proof_hash_size(field, 31);
    REQUIRE_THROWS_AS(
      ccf::cose::recompute_merkle_root(malformed), ccf::cose::COSEDecodeError);
  }
}

TEST_CASE("COSE verifier imports public keys and certificates")
{
  // Generate a fresh key pair and self-signed certificate.
  auto kp = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  auto cert_pem = kp->self_sign(
    "CN=test", "20200101000000Z", "20301231235959Z", std::nullopt, true);
  auto cert_der = ccf::crypto::cert_pem_to_der(cert_pem);

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {0xCA, 0xFE};
  const auto envelope =
    ccf::cose::sign_endorsement(*kp, 1700000000, epoch_begin, {}, {}, payload);

  SUBCASE("PEM public key")
  {
    auto verifier =
      ccf::crypto::make_cose_verifier_from_key(kp->public_key_pem());
    std::span<uint8_t> authned;
    CHECK(verifier->verify(envelope, authned));
  }

  SUBCASE("PEM certificate bytes")
  {
    std::vector<uint8_t> pem_bytes(
      cert_pem.data(), cert_pem.data() + cert_pem.size());
    auto verifier = ccf::crypto::make_cose_verifier_any_cert(pem_bytes);
    std::span<uint8_t> authned;
    CHECK(verifier->verify(envelope, authned));
    verifier = ccf::crypto::make_cose_verifier_from_pem_cert(cert_pem);
    CHECK(verifier->verify(envelope, authned));
    CHECK_THROWS_AS(
      ccf::crypto::make_cose_verifier_from_der_cert(pem_bytes),
      std::invalid_argument);
  }

  SUBCASE("DER certificate bytes")
  {
    auto verifier = ccf::crypto::make_cose_verifier_any_cert(cert_der);
    std::span<uint8_t> authned;
    CHECK(verifier->verify(envelope, authned));
    verifier = ccf::crypto::make_cose_verifier_from_der_cert(cert_der);
    CHECK(verifier->verify(envelope, authned));
    verifier = ccf::crypto::make_cose_verifier_from_key(
      ccf::crypto::COSEKey::from_der_cert(cert_der));
    CHECK(verifier->verify(envelope, authned));
  }

  SUBCASE("unsupported certificate key type")
  {
    // Test-only key on a valid EC curve that COSE verification rejects.
    const ccf::crypto::Pem secp256k1_key(
      "-----BEGIN PUBLIC KEY-----\n"
      "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEgg35KU1dh2JezYWNWE1uGkQLG+NiLfje\n"
      "WJQtjC/UjQHVQVWvlfifZuz2jYYl9SehNLb7dMeVjcK6zloSMJz1Uw==\n"
      "-----END PUBLIC KEY-----\n");
    for (const auto& subject_key :
         {ccf::crypto::make_eddsa_key_pair()->public_key_pem(), secp256k1_key})
    {
      const auto unsupported_cert = ccf::crypto::create_endorsed_cert(
        subject_key,
        "CN=unsupported COSE key",
        {},
        "20200101000000Z",
        "20301231235959Z",
        kp->private_key_pem(),
        cert_pem);
      CHECK_THROWS_AS(
        ccf::crypto::make_cose_verifier_any_cert(unsupported_cert.raw()),
        std::invalid_argument);
      CHECK_THROWS_AS(
        ccf::crypto::make_cose_verifier_from_pem_cert(unsupported_cert),
        std::invalid_argument);
      CHECK_THROWS_AS(
        ccf::crypto::make_cose_verifier_from_key(subject_key),
        std::runtime_error);
    }
  }

  SUBCASE("invalid certificate public key")
  {
    auto invalid_der = cert_der;
    const auto public_key = kp->public_key_der();
    auto key_in_cert = std::search(
      invalid_der.begin(),
      invalid_der.end(),
      public_key.begin(),
      public_key.end());
    REQUIRE(key_in_cert != invalid_der.end());
    // Keep the certificate parseable but move its EC point off the curve.
    *(key_in_cert + public_key.size() - 1) ^= 0xff;
    CHECK_THROWS_WITH_AS(
      ccf::crypto::make_cose_verifier_from_der_cert(invalid_der),
      doctest::Contains("Failed to get certificate public key"),
      std::invalid_argument);
  }

  SUBCASE("garbage bytes fail")
  {
    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
    CHECK_THROWS_WITH_AS(
      ccf::crypto::make_cose_verifier_from_key(std::span<const uint8_t>{}),
      "Invalid public key size",
      std::runtime_error);
    CHECK_THROWS_WITH_AS(
      ccf::crypto::make_cose_verifier_any_cert({}),
      "Invalid certificate size",
      std::invalid_argument);
    CHECK_THROWS_WITH_AS(
      ccf::crypto::make_cose_verifier_from_der_cert({}),
      "Invalid certificate size",
      std::invalid_argument);
    CHECK_THROWS_AS(
      ccf::crypto::make_cose_verifier_any_cert(garbage), std::invalid_argument);
    CHECK_THROWS_AS(
      ccf::crypto::make_cose_verifier_from_der_cert(garbage),
      std::invalid_argument);
    CHECK_THROWS_WITH_AS(
      ccf::crypto::make_cose_verifier_from_key(garbage),
      doctest::Contains("Failed to parse public key"),
      std::runtime_error);
    const ccf::crypto::Pem invalid_key(
      "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----");
    CHECK_THROWS_WITH_AS(
      ccf::crypto::make_cose_verifier_from_key(invalid_key),
      doctest::Contains("Failed to parse public key"),
      std::runtime_error);
    const ccf::crypto::Pem invalid_cert(
      "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----");
    CHECK_THROWS_AS(
      ccf::crypto::make_cose_verifier_from_pem_cert(invalid_cert),
      std::invalid_argument);
  }
}

TEST_CASE("ECDSA algorithm identifiers")
{
  // Deprecated ES identifiers.
  REQUIRE(ccf::cose::is_ecdsa_alg(-7)); // ES256
  REQUIRE(ccf::cose::is_ecdsa_alg(-35)); // ES384
  REQUIRE(ccf::cose::is_ecdsa_alg(-36)); // ES512

  // Fully-specified ESP identifiers, as introduced by RFC 9864.
  REQUIRE(ccf::cose::is_ecdsa_alg(-9)); // ESP256
  REQUIRE(ccf::cose::is_ecdsa_alg(-51)); // ESP384
  REQUIRE(ccf::cose::is_ecdsa_alg(-52)); // ESP512

  REQUIRE_FALSE(ccf::cose::is_ecdsa_alg(-8)); // EdDSA
  REQUIRE_FALSE(ccf::cose::is_ecdsa_alg(-37)); // PS256
  REQUIRE_FALSE(ccf::cose::is_ecdsa_alg(-47)); // ES256K
  REQUIRE_FALSE(ccf::cose::is_ecdsa_alg(0));

  REQUIRE(ccf::cose::is_rsa_alg(-37)); // PS256
  REQUIRE(ccf::cose::is_rsa_alg(-38)); // PS384
  REQUIRE(ccf::cose::is_rsa_alg(-39)); // PS512
  REQUIRE_FALSE(ccf::cose::is_rsa_alg(-9));
  REQUIRE_FALSE(ccf::cose::is_rsa_alg(-7));
}

// COSE_Key labels
constexpr int64_t LABEL_KTY = 1;
constexpr int64_t LABEL_KID = 2;
constexpr int64_t LABEL_ALG = 3;
constexpr int64_t LABEL_KEY_OPS = 4;
constexpr int64_t LABEL_EC2_CRV = -1;
constexpr int64_t LABEL_EC2_X = -2;
constexpr int64_t LABEL_EC2_Y = -3;
constexpr int64_t LABEL_EC2_D = -4;
constexpr int64_t LABEL_RSA_N = -1;
constexpr int64_t LABEL_RSA_E = -2;
constexpr int64_t LABEL_RSA_D = -3;

// Values of COSE_Key fields, to build valid and malformed keys
using CoseKeyField = std::variant<
  int64_t,
  std::vector<uint8_t>,
  std::string,
  bool,
  std::vector<int64_t>>;
using CoseKeyFields = std::vector<std::pair<int64_t, CoseKeyField>>;

template <typename... Fs>
struct Overloaded : Fs...
{
  using Fs::operator()...;
};

static std::vector<uint8_t> encode_cose_key_fields(const CoseKeyFields& fields)
{
  using namespace tav::cbor;
  const Overloaded to_value{
    [](int64_t value) { return make_signed(value); },
    [](const std::vector<uint8_t>& value) { return make_bytes(value); },
    [](const std::string& value) { return make_string(value); },
    [](bool value) {
      return make_simple(value ? SimpleValue::True : SimpleValue::False);
    },
    [](const std::vector<int64_t>& values) {
      std::vector<Value> array;
      for (const auto value : values)
      {
        array.push_back(make_signed(value));
      }
      return make_array(std::move(array));
    }};
  std::vector<MapItem> items;
  for (const auto& [label, field] : fields)
  {
    items.emplace_back(make_signed(label), std::visit(to_value, field));
  }
  return make_map(std::move(items)).nondet_serialize();
}

// The fields with label set to field
static std::vector<uint8_t> encode_with(
  CoseKeyFields fields, int64_t label, CoseKeyField field)
{
  std::erase_if(
    fields, [label](const auto& entry) { return entry.first == label; });
  fields.emplace_back(label, std::move(field));
  return encode_cose_key_fields(fields);
}

// The fields without label
static std::vector<uint8_t> encode_without(CoseKeyFields fields, int64_t label)
{
  std::erase_if(
    fields, [label](const auto& entry) { return entry.first == label; });
  return encode_cose_key_fields(fields);
}

static CoseKeyFields ec2_fields(const ccf::crypto::COSEKey::EC2Parameters& key)
{
  return {
    {LABEL_KTY, int64_t{2}},
    {LABEL_EC2_CRV, key.crv},
    {LABEL_EC2_X, key.x},
    {LABEL_EC2_Y, key.y}};
}

static ccf::crypto::COSEKey random_ec_cose_key(ccf::crypto::CurveID curve)
{
  return ccf::crypto::COSEKey(ccf::crypto::make_ec_public_key(
    ccf::crypto::make_ec_key_pair(curve)->public_key_der()));
}

// x + p for P-521, whose prime p = 2^521 - 1 still fits in 66 bytes: the same
// point, encoded with a coordinate that is not below the field prime.
static std::vector<uint8_t> add_p521_prime(std::vector<uint8_t> x)
{
  REQUIRE(x.size() == 66);
  unsigned carry = 0;
  for (size_t i = x.size(); i-- > 0;)
  {
    const unsigned p_byte = i == 0 ? 0x01 : 0xff;
    const unsigned sum = x[i] + p_byte + carry;
    x[i] = static_cast<uint8_t>(sum & 0xff);
    carry = sum >> 8;
  }
  REQUIRE(carry == 0);
  return x;
}

TEST_CASE("COSE_Key encoding and thumbprints")
{
  using ccf::crypto::COSEKey;
  using ccf::ds::from_hex;

  // RFC 9679 Section 6
  const std::string x =
    "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
  const std::string y =
    "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
  const std::string thumbprint =
    "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec";
  // {1: 2, -1: 1, -2: x, -3: y, 2: thumbprint}
  const auto ec_key = COSEKey::from_cbor(
    from_hex("a501022001215820" + x + "225820" + y + "025820" + thumbprint));
  // The thumbprint input: {1: 2, -1: 1, -2: x, -3: y}
  CHECK(ec_key.to_cbor() == from_hex("a401022001215820" + x + "225820" + y));
  CHECK(ec_key.thumbprint_sha256().hex_str() == thumbprint);
  // {1: 2, 2: 'kid-1', -1: 1, -2: x, -3: y}
  CHECK(
    ec_key.to_cbor("kid-1") ==
    from_hex("a5010202456b69642d312001215820" + x + "225820" + y));
  const auto ec2 = ec_key.ec2_parameters().value();
  CHECK(ec2.crv == 1);
  CHECK(ec2.x == from_hex(x));
  CHECK(ec2.y == from_hex(y));

  // RSA-2048, computed independently of this code, with n and e in their
  // minimal encoding (RFC 8230 Section 4)
  const std::string n =
    "d3ee08a208d1f77305370d8caf1573927be7bd07965f386f8b07bff4b489dfad93ed95b5"
    "b48a5e5e1c541970bc8d9a5c32b7c140e70dc84133e730e74ee9563d64772dc35c8bf816"
    "e4b12b5b91e662fd903f73e5009f48e1c0317658d0fb869e10852af6bfa1656457185250"
    "49ea4425f37e891614957be33aac2fe812d7b2f3cb4bcb3356a4939975427e5bc76b871a"
    "697729eb81ca80b378492849aeee6aa339e97c853dcba5ce2ced58fd6d4bbadcbd12145c"
    "7fb24f22ae32078efe8a302d856388a79e86aafc33bc129103b757f26455c82d7fbec643"
    "18ca9bd74635b5a6601c6cbc9ce128a0c8ba9a50c2ba64d413be21f59dc3f38ece21261e"
    "0b9362d5";
  // {1: 3, -1: n, -2: h'010001'}
  const auto rsa_encoded = from_hex("a3010320590100" + n + "2143010001");
  const auto rsa_key = COSEKey::from_cbor(rsa_encoded);
  CHECK(rsa_key.to_cbor() == rsa_encoded);
  CHECK(
    rsa_key.thumbprint_sha256().hex_str() ==
    "f968d08ed6fabc601c720a0757ef9b75ff9ea079dd1e47a12a7b0fc7fab39112");
  const auto rsa = rsa_key.rsa_parameters().value();
  CHECK(rsa.n == from_hex(n));
  CHECK(rsa.e == std::vector<uint8_t>{0x01, 0x00, 0x01});
}

TEST_CASE("COSE_Key round trips")
{
  using ccf::crypto::COSEKey;
  using ccf::crypto::COSEKeyType;
  using ccf::crypto::CurveID;

  for (const auto& [curve, coordinate_size] :
       {std::pair{CurveID::SECP256R1, size_t{32}},
        std::pair{CurveID::SECP384R1, size_t{48}},
        std::pair{CurveID::SECP521R1, size_t{66}}})
  {
    CAPTURE(coordinate_size);
    const auto key = random_ec_cose_key(curve);
    const auto encoded = key.to_cbor("kid");
    const auto parsed = COSEKey::from_cbor(encoded);
    REQUIRE(parsed.kty() == COSEKeyType::EC2);
    CHECK_FALSE(parsed.alg().has_value());
    CHECK(parsed.to_cbor("kid") == encoded);
    CHECK(parsed.thumbprint_sha256() == ccf::crypto::Sha256Hash(key.to_cbor()));
    CHECK(
      parsed.ec_public_key()->public_key_der() ==
      key.ec_public_key()->public_key_der());
    CHECK(parsed.rsa_public_key() == nullptr);
    CHECK_FALSE(parsed.rsa_parameters().has_value());
    // Coordinates keep any leading zero octets
    const auto parameters = parsed.ec2_parameters().value();
    CHECK(parameters.x.size() == coordinate_size);
    CHECK(parameters.y.size() == coordinate_size);
  }

  const COSEKey rsa_key(ccf::crypto::make_rsa_key_pair());
  const auto encoded = rsa_key.to_cbor("kid");
  const auto parsed = COSEKey::from_cbor(encoded);
  REQUIRE(parsed.kty() == COSEKeyType::RSA);
  CHECK_FALSE(parsed.alg().has_value());
  CHECK(parsed.to_cbor("kid") == encoded);
  CHECK(
    parsed.thumbprint_sha256() == ccf::crypto::Sha256Hash(rsa_key.to_cbor()));
  CHECK(
    parsed.rsa_public_key()->public_key_der() ==
    rsa_key.rsa_public_key()->public_key_der());
  CHECK(parsed.ec_public_key() == nullptr);
  CHECK_FALSE(parsed.ec2_parameters().has_value());

  CHECK_THROWS_AS(
    COSEKey(ccf::crypto::ECPublicKeyPtr{}), std::invalid_argument);
  CHECK_THROWS_AS(
    COSEKey(ccf::crypto::RSAPublicKeyPtr{}), std::invalid_argument);
}

TEST_CASE("COSE_Key parsing rejects malformed and unsupported keys")
{
  using ccf::crypto::COSEKey;
  using ccf::crypto::CurveID;

  const auto p256 =
    random_ec_cose_key(CurveID::SECP256R1).ec2_parameters().value();
  const auto p521 =
    random_ec_cose_key(CurveID::SECP521R1).ec2_parameters().value();
  const auto rsa =
    COSEKey(ccf::crypto::make_rsa_key_pair()).rsa_parameters().value();
  const auto p256_key = ec2_fields(p256);
  const CoseKeyFields rsa_key = {
    {LABEL_KTY, int64_t{3}}, {LABEL_RSA_N, rsa.n}, {LABEL_RSA_E, rsa.e}};

  // Valid keys, and edits of them that are still accepted
  for (const auto& accepted : {
         encode_cose_key_fields(p256_key),
         encode_cose_key_fields(rsa_key),
         encode_with(p256_key, LABEL_KID, std::vector<uint8_t>{1, 2}),
         encode_with(p256_key, LABEL_KEY_OPS, std::vector<int64_t>{1, 2}),
         encode_with(p256_key, 100, std::string("unknown label")),
         encode_with(rsa_key, LABEL_ALG, int64_t{-37}), // PS256
       })
  {
    CHECK_NOTHROW(std::ignore = COSEKey::from_cbor(accepted));
  }

  auto short_x = p256.x;
  short_x.erase(short_x.begin());
  auto long_x = p256.x;
  long_x.push_back(0);
  auto off_curve_y = p256.y;
  off_curve_y.back() ^= 0xff;
  auto padded_n = rsa.n;
  padded_n.insert(padded_n.begin(), 0);
  auto padded_e = rsa.e;
  padded_e.insert(padded_e.begin(), 0);
  const std::vector<uint8_t> short_n(rsa.n.begin(), rsa.n.begin() + 128);
  auto trailing_bytes = encode_cose_key_fields(p256_key);
  trailing_bytes.push_back(0);

  const std::vector<std::pair<std::string, std::vector<uint8_t>>> rejected = {
    {"not CBOR", ccf::ds::from_hex("ff")},
    {"not a map", ccf::ds::from_hex("80")},
    {"trailing bytes", trailing_bytes},
    {"kty missing", encode_without(p256_key, LABEL_KTY)},
    {"kty text", encode_with(p256_key, LABEL_KTY, std::string("EC2"))},
    {"kty OKP", encode_with(p256_key, LABEL_KTY, int64_t{1})},
    {"kid text", encode_with(p256_key, LABEL_KID, std::string("kid"))},
    {"alg text", encode_with(p256_key, LABEL_ALG, std::string("ES256"))},
    {"alg EdDSA", encode_with(p256_key, LABEL_ALG, int64_t{-8})},
    {"alg for P-384", encode_with(p256_key, LABEL_ALG, int64_t{-35})},
    {"alg for RSA", encode_with(p256_key, LABEL_ALG, int64_t{-37})},
    {"key_ops not an array", encode_with(p256_key, LABEL_KEY_OPS, int64_t{2})},
    {"key_ops without verify",
     encode_with(p256_key, LABEL_KEY_OPS, std::vector<int64_t>{1})},
    {"crv missing", encode_without(p256_key, LABEL_EC2_CRV)},
    {"crv text", encode_with(p256_key, LABEL_EC2_CRV, std::string("P-256"))},
    {"crv secp256k1", encode_with(p256_key, LABEL_EC2_CRV, int64_t{8})},
    {"x missing", encode_without(p256_key, LABEL_EC2_X)},
    {"x too short", encode_with(p256_key, LABEL_EC2_X, short_x)},
    {"x too long", encode_with(p256_key, LABEL_EC2_X, long_x)},
    {"y missing", encode_without(p256_key, LABEL_EC2_Y)},
    {"y compressed", encode_with(p256_key, LABEL_EC2_Y, true)},
    {"point not on the curve", encode_with(p256_key, LABEL_EC2_Y, off_curve_y)},
    {"x not below the field prime",
     encode_with(ec2_fields(p521), LABEL_EC2_X, add_p521_prime(p521.x))},
    {"EC2 private key",
     encode_with(p256_key, LABEL_EC2_D, std::vector<uint8_t>(32, 1))},
    {"n missing", encode_without(rsa_key, LABEL_RSA_N)},
    {"n with leading zero", encode_with(rsa_key, LABEL_RSA_N, padded_n)},
    {"n below 2048 bits", encode_with(rsa_key, LABEL_RSA_N, short_n)},
    {"e with leading zero", encode_with(rsa_key, LABEL_RSA_E, padded_e)},
    {"e even",
     encode_with(rsa_key, LABEL_RSA_E, std::vector<uint8_t>{1, 0, 0})},
    {"e one", encode_with(rsa_key, LABEL_RSA_E, std::vector<uint8_t>{1})},
    {"RSA private key",
     encode_with(rsa_key, LABEL_RSA_D, std::vector<uint8_t>{1})},
  };
  for (const auto& [name, encoded] : rejected)
  {
    CAPTURE(name);
    CHECK_THROWS_AS(
      std::ignore = COSEKey::from_cbor(encoded), std::invalid_argument);
  }
}

TEST_CASE("COSE_Key alg restricts verification")
{
  using ccf::crypto::COSEKey;

  const auto key_pair =
    ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  // Signed with ES384 (-35)
  const auto envelope = ccf::cose::sign_endorsement(
    *key_pair, 1700000000, "2.1", {}, {}, detached_payload);
  const auto fields =
    tav::cbor::nondet_parse(envelope).tag_at(ccf::cbor::tag::COSE_SIGN_1);
  const auto phdr = fields.array_at(0).as_bytes();
  const auto sig = fields.array_at(3).as_bytes();

  const COSEKey key(
    ccf::crypto::make_ec_public_key(key_pair->public_key_der()));
  // Restricted to ESP384 (-51)
  const auto restricted = COSEKey::from_cbor(encode_with(
    ec2_fields(key.ec2_parameters().value()), LABEL_ALG, int64_t{-51}));
  CHECK(restricted.alg() == -51);
  CHECK(COSEKey::from_cbor(restricted.to_cbor()).alg() == -51);
  // alg is not part of the thumbprint input
  CHECK(restricted.thumbprint_sha256() == key.thumbprint_sha256());

  std::span<uint8_t> authenticated;
  CHECK(ccf::crypto::make_cose_verifier_from_key(key)->verify(
    envelope, authenticated));
  const auto verifier = ccf::crypto::make_cose_verifier_from_key(restricted);
  CHECK_FALSE(verifier->verify(envelope, authenticated));
  CHECK(verifier->verify_decomposed(phdr, detached_payload, sig, -51));
}
