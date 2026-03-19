// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "cose_rs_ffi.h"
#include "crypto/cbor.h"
#include "crypto/cose.h"
#include "crypto/openssl/ec_key_pair.h"

#include <doctest/doctest.h>
#include <string>
#include <vector>

namespace
{
  struct TestKey
  {
    ccf::crypto::ECKeyPair_OpenSSL kp;
    std::vector<uint8_t> priv_der;
    std::vector<uint8_t> pub_der;

    TestKey(ccf::crypto::CurveID curve = ccf::crypto::CurveID::SECP384R1) :
      kp(curve),
      priv_der(kp.private_key_der()),
      pub_der(kp.public_key_der())
    {}
  };

  struct CoseSign1Components
  {
    std::span<const uint8_t> phdr;
    std::optional<std::span<const uint8_t>> payload;
    std::span<const uint8_t> sig;
    int64_t alg;
  };

  CoseSign1Components decompose(const std::vector<uint8_t>& envelope)
  {
    using namespace ccf::cbor;
    auto cose = parse(envelope);
    const auto& env = cose->tag_at(ccf::cbor::tag::COSE_SIGN_1);
    auto phdr = env->array_at(0)->as_bytes();

    std::optional<std::span<const uint8_t>> payload;
    try
    {
      payload = env->array_at(2)->as_bytes();
    }
    catch (const CBORDecodeError&)
    {
      if (env->array_at(2)->as_simple() != ccf::cbor::SimpleValue::Null)
      {
        throw;
      }
    }

    auto sig = env->array_at(3)->as_bytes();

    auto phdr_parsed = parse({phdr.data(), phdr.size()});
    auto alg = phdr_parsed->map_at(make_signed(ccf::cose::header::iana::ALG))
                 ->as_signed();

    return {phdr, payload, sig, alg};
  }

  int verify_decoded(
    const std::vector<uint8_t>& pub_der,
    const CoseSign1Components& c,
    std::span<const uint8_t> payload)
  {
    return cose_verify1(
      pub_der.data(),
      pub_der.size(),
      c.alg,
      c.phdr.data(),
      c.phdr.size(),
      payload.data(),
      payload.size(),
      c.sig.data(),
      c.sig.size());
  }
}

TEST_CASE("cose_sign_ledger sign and verify round-trip")
{
  TestKey key;

  const std::string kid = "test-kid";
  const std::string issuer = "test-issuer";
  const std::string subject = "test-subject";
  const std::string txid = "2.42";
  const std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
  const int64_t iat = 1700000000;

  CoseBuffer buf;
  auto rc = cose_sign_ledger(
    key.priv_der.data(),
    key.priv_der.size(),
    reinterpret_cast<const uint8_t*>(kid.data()),
    kid.size(),
    iat,
    reinterpret_cast<const uint8_t*>(issuer.data()),
    issuer.size(),
    reinterpret_cast<const uint8_t*>(subject.data()),
    subject.size(),
    reinterpret_cast<const uint8_t*>(txid.data()),
    txid.size(),
    payload.data(),
    payload.size(),
    buf);

  REQUIRE(rc == 0);
  REQUIRE(buf.ok());

  auto envelope = buf.to_vector();
  REQUIRE(!envelope.empty());

  auto c = decompose(envelope);
  CHECK(verify_decoded(key.pub_der, c, payload) == 0);

  std::vector<uint8_t> wrong_payload = {9, 8, 7};
  CHECK(verify_decoded(key.pub_der, c, wrong_payload) != 0);
}

TEST_CASE("cose_sign_ledger fails with invalid key")
{
  const std::vector<uint8_t> bad_key = {0, 1, 2, 3};
  const std::string kid = "k";
  const std::string issuer = "i";
  const std::string subject = "s";
  const std::string txid = "1.1";
  const std::vector<uint8_t> payload = {1};

  CoseBuffer buf;
  auto rc = cose_sign_ledger(
    bad_key.data(),
    bad_key.size(),
    reinterpret_cast<const uint8_t*>(kid.data()),
    kid.size(),
    0,
    reinterpret_cast<const uint8_t*>(issuer.data()),
    issuer.size(),
    reinterpret_cast<const uint8_t*>(subject.data()),
    subject.size(),
    reinterpret_cast<const uint8_t*>(txid.data()),
    txid.size(),
    payload.data(),
    payload.size(),
    buf);

  CHECK(rc != 0);
  CHECK(!buf.ok());
}

TEST_CASE("cose_sign_endorsement sign and verify round-trip")
{
  TestKey key;

  const std::string epoch_begin = "2.1";
  const std::string epoch_end = "3.10";
  const std::vector<uint8_t> prev_root = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
  const std::vector<uint8_t> payload = {10, 20, 30};
  const int64_t iat = 1700000000;

  CoseBuffer buf;
  auto rc = cose_sign_endorsement(
    key.priv_der.data(),
    key.priv_der.size(),
    iat,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    reinterpret_cast<const uint8_t*>(epoch_end.data()),
    epoch_end.size(),
    prev_root.data(),
    prev_root.size(),
    payload.data(),
    payload.size(),
    buf);

  REQUIRE(rc == 0);
  REQUIRE(buf.ok());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);
  CHECK(verify_decoded(key.pub_der, c, c.payload.value()) == 0);
}

TEST_CASE("cose_sign_endorsement without optional fields")
{
  TestKey key;

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {42};
  const int64_t iat = 1700000000;

  CoseBuffer buf;
  auto rc = cose_sign_endorsement(
    key.priv_der.data(),
    key.priv_der.size(),
    iat,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf);

  REQUIRE(rc == 0);
  REQUIRE(buf.ok());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);
  CHECK(verify_decoded(key.pub_der, c, c.payload.value()) == 0);
}

TEST_CASE("cose_verify1 fails with wrong key")
{
  TestKey sign_key;
  TestKey wrong_key;

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {1, 2, 3};

  CoseBuffer buf;
  cose_sign_endorsement(
    sign_key.priv_der.data(),
    sign_key.priv_der.size(),
    0,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf);
  REQUIRE(buf.ok());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);
  CHECK(verify_decoded(wrong_key.pub_der, c, c.payload.value()) != 0);
}

TEST_CASE("cose_verify1 fails with corrupted signature")
{
  TestKey key;

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {1, 2, 3};

  CoseBuffer buf;
  cose_sign_endorsement(
    key.priv_der.data(),
    key.priv_der.size(),
    0,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf);
  REQUIRE(buf.ok());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);

  std::vector<uint8_t> bad_sig(c.sig.begin(), c.sig.end());
  bad_sig[bad_sig.size() - 1] ^= 0xFF;

  auto vrc = cose_verify1(
    key.pub_der.data(),
    key.pub_der.size(),
    c.alg,
    c.phdr.data(),
    c.phdr.size(),
    c.payload.value().data(),
    c.payload.value().size(),
    bad_sig.data(),
    bad_sig.size());
  CHECK(vrc != 0);
}

TEST_CASE("cose_verify1 wrong alg fails")
{
  TestKey key;

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {0xCA, 0xFE};

  CoseBuffer buf;
  cose_sign_endorsement(
    key.priv_der.data(),
    key.priv_der.size(),
    0,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf);
  REQUIRE(buf.ok());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);

  CHECK(verify_decoded(key.pub_der, c, c.payload.value()) == 0);

  auto payload_span = c.payload.value();
  auto vrc = cose_verify1(
    key.pub_der.data(),
    key.pub_der.size(),
    -7,
    c.phdr.data(),
    c.phdr.size(),
    payload_span.data(),
    payload_span.size(),
    c.sig.data(),
    c.sig.size());
  CHECK(vrc != 0);
}

TEST_CASE("CoseBuffer RAII semantics")
{
  SUBCASE("default construction")
  {
    CoseBuffer buf;
    CHECK(!buf.ok());
    CHECK(buf.to_vector().empty());
  }

  SUBCASE("move construction")
  {
    TestKey key;
    const std::string epoch_begin = "1.1";
    const std::vector<uint8_t> payload = {1};

    CoseBuffer buf;
    cose_sign_endorsement(
      key.priv_der.data(),
      key.priv_der.size(),
      0,
      reinterpret_cast<const uint8_t*>(epoch_begin.data()),
      epoch_begin.size(),
      nullptr,
      0,
      nullptr,
      0,
      payload.data(),
      payload.size(),
      buf);
    REQUIRE(buf.ok());

    auto vec_before = buf.to_vector();
    CoseBuffer moved(std::move(buf));
    CHECK(!buf.ok());
    CHECK(moved.ok());
    CHECK(moved.to_vector() == vec_before);
  }

  SUBCASE("reset")
  {
    TestKey key;
    const std::string epoch_begin = "1.1";
    const std::vector<uint8_t> payload = {1};

    CoseBuffer buf;
    cose_sign_endorsement(
      key.priv_der.data(),
      key.priv_der.size(),
      0,
      reinterpret_cast<const uint8_t*>(epoch_begin.data()),
      epoch_begin.size(),
      nullptr,
      0,
      nullptr,
      0,
      payload.data(),
      payload.size(),
      buf);
    REQUIRE(buf.ok());

    buf.reset();
    CHECK(!buf.ok());
  }
}

TEST_CASE("cose_free with null is safe")
{
  cose_free(nullptr, 0);
  cose_free(nullptr, 100);
}
