// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/crypto/verifier.h"
#include "cose/cose_rs_ffi.h"
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
    std::span<const uint8_t> payload,
    CoseBuffer* out_err = nullptr)
  {
    CoseBuffer key_err;
    auto vkey = CoseKey::from_public(pub_der.data(), pub_der.size(), key_err);
    CoseBuffer err;
    auto rc = cose_verify1(
      vkey,
      c.alg,
      c.phdr.data(),
      c.phdr.size(),
      payload.data(),
      payload.size(),
      c.sig.data(),
      c.sig.size(),
      err);
    if (out_err)
    {
      *out_err = std::move(err);
    }
    return rc;
  }
}

TEST_CASE("cose_sign_ledger sign and verify round-trip")
{
  TestKey key;
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
  REQUIRE(cose_key.is_set());

  const std::string kid = "test-kid";
  const std::string issuer = "test-issuer";
  const std::string subject = "test-subject";
  const std::string txid = "2.42";
  const std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
  const int64_t iat = 1700000000;

  CoseBuffer buf;
  CoseBuffer sign_err;
  auto rc = cose_sign_ledger(
    cose_key,
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
    buf,
    sign_err);

  REQUIRE(rc == 0);
  REQUIRE(buf.is_set());

  auto envelope = buf.to_vector();
  REQUIRE(!envelope.empty());

  auto c = decompose(envelope);
  CHECK(verify_decoded(key.pub_der, c, payload) == 0);

  std::vector<uint8_t> wrong_payload = {9, 8, 7};
  CoseBuffer wrong_err;
  CHECK(verify_decoded(key.pub_der, c, wrong_payload, &wrong_err) != 0);
  CHECK(wrong_err.to_string() == "Signature verification failed");
}

TEST_CASE("cose_sign_ledger fails with invalid key")
{
  const std::vector<uint8_t> bad_key = {0, 1, 2, 3};
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(bad_key.data(), bad_key.size(), key_err);
  CHECK(!cose_key.is_set());
  CHECK(key_err.is_set());
  CHECK(
    key_err.to_string().find("d2i_AutoPrivateKey failed:") !=
    std::string::npos);
}

TEST_CASE("CoseKey error propagation")
{
  SUBCASE("null DER pointer")
  {
    CoseBuffer err;
    auto k = CoseKey::from_private(nullptr, 0, err);
    CHECK(!k.is_set());
  }

  SUBCASE("truncated DER returns OpenSSL error detail")
  {
    // A plausible but truncated EC private key prefix.
    const std::vector<uint8_t> truncated = {0x30, 0x81, 0x87, 0x02, 0x01};
    CoseBuffer err;
    auto k = CoseKey::from_private(truncated.data(), truncated.size(), err);
    CHECK(!k.is_set());
    CHECK(err.is_set());
    CHECK(
      err.to_string().find("d2i_AutoPrivateKey failed:") != std::string::npos);
  }

  SUBCASE("valid key succeeds without error")
  {
    TestKey tk;
    CoseBuffer err;
    auto k = CoseKey::from_private(tk.priv_der.data(), tk.priv_der.size(), err);
    CHECK(k.is_set());
    CHECK(!err.is_set());
  }

  SUBCASE("move preserves key validity")
  {
    TestKey tk;
    CoseBuffer err;
    auto k = CoseKey::from_private(tk.priv_der.data(), tk.priv_der.size(), err);
    REQUIRE(k.is_set());

    CoseKey moved(std::move(k));
    CHECK(!k.is_set());
    CHECK(moved.is_set());
  }

  SUBCASE("reset releases key")
  {
    TestKey tk;
    CoseBuffer err;
    auto k = CoseKey::from_private(tk.priv_der.data(), tk.priv_der.size(), err);
    REQUIRE(k.is_set());

    k.reset();
    CHECK(!k.is_set());
  }
}

TEST_CASE("cose_sign_endorsement sign and verify round-trip")
{
  TestKey key;
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
  REQUIRE(cose_key.is_set());

  const std::string epoch_begin = "2.1";
  const std::string epoch_end = "3.10";
  const std::vector<uint8_t> prev_root = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
  const std::vector<uint8_t> payload = {10, 20, 30};
  const int64_t iat = 1700000000;

  CoseBuffer buf;
  CoseBuffer sign_err;
  auto rc = cose_sign_endorsement(
    cose_key,
    iat,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    reinterpret_cast<const uint8_t*>(epoch_end.data()),
    epoch_end.size(),
    prev_root.data(),
    prev_root.size(),
    payload.data(),
    payload.size(),
    buf,
    sign_err);

  REQUIRE(rc == 0);
  REQUIRE(buf.is_set());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);
  CHECK(verify_decoded(key.pub_der, c, c.payload.value()) == 0);
}

TEST_CASE("cose_sign_endorsement without optional fields")
{
  TestKey key;
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
  REQUIRE(cose_key.is_set());

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {42};
  const int64_t iat = 1700000000;

  CoseBuffer buf;
  CoseBuffer sign_err;
  auto rc = cose_sign_endorsement(
    cose_key,
    iat,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf,
    sign_err);

  REQUIRE(rc == 0);
  REQUIRE(buf.is_set());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);
  CHECK(verify_decoded(key.pub_der, c, c.payload.value()) == 0);
}

TEST_CASE("cose_verify1 fails with wrong key")
{
  TestKey sign_key;
  CoseBuffer key_err;
  auto sign_cose_key = CoseKey::from_private(
    sign_key.priv_der.data(), sign_key.priv_der.size(), key_err);
  REQUIRE(sign_cose_key.is_set());
  TestKey wrong_key;

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {1, 2, 3};

  CoseBuffer buf;
  CoseBuffer sign_err;
  cose_sign_endorsement(
    sign_cose_key,
    0,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf,
    sign_err);
  REQUIRE(buf.is_set());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);
  CoseBuffer wrong_key_err;
  CHECK(
    verify_decoded(wrong_key.pub_der, c, c.payload.value(), &wrong_key_err) !=
    0);
  CHECK(wrong_key_err.to_string() == "Signature verification failed");
}

TEST_CASE("cose_verify1 fails with corrupted signature")
{
  TestKey key;
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
  REQUIRE(cose_key.is_set());

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {1, 2, 3};

  CoseBuffer buf;
  CoseBuffer sign_err;
  cose_sign_endorsement(
    cose_key,
    0,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf,
    sign_err);
  REQUIRE(buf.is_set());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);

  std::vector<uint8_t> bad_sig(c.sig.begin(), c.sig.end());
  bad_sig[bad_sig.size() - 1] ^= 0xFF;

  CoseBuffer vkey_err;
  auto vkey =
    CoseKey::from_public(key.pub_der.data(), key.pub_der.size(), vkey_err);
  CoseBuffer verify_err;
  auto vrc = cose_verify1(
    vkey,
    c.alg,
    c.phdr.data(),
    c.phdr.size(),
    c.payload.value().data(),
    c.payload.value().size(),
    bad_sig.data(),
    bad_sig.size(),
    verify_err);
  CHECK(vrc != 0);
  CHECK(verify_err.is_set());
  CHECK(verify_err.to_string() == "Signature verification failed");
}

TEST_CASE("cose_verify1 wrong alg fails")
{
  TestKey key;
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
  REQUIRE(cose_key.is_set());

  const std::string epoch_begin = "1.1";
  const std::vector<uint8_t> payload = {0xCA, 0xFE};

  CoseBuffer buf;
  CoseBuffer sign_err;
  cose_sign_endorsement(
    cose_key,
    0,
    reinterpret_cast<const uint8_t*>(epoch_begin.data()),
    epoch_begin.size(),
    nullptr,
    0,
    nullptr,
    0,
    payload.data(),
    payload.size(),
    buf,
    sign_err);
  REQUIRE(buf.is_set());

  auto envelope = buf.to_vector();
  auto c = decompose(envelope);

  CHECK(verify_decoded(key.pub_der, c, c.payload.value()) == 0);

  auto payload_span = c.payload.value();
  CoseBuffer vkey_err;
  auto vkey =
    CoseKey::from_public(key.pub_der.data(), key.pub_der.size(), vkey_err);
  CoseBuffer verify_err;
  auto vrc = cose_verify1(
    vkey,
    -7,
    c.phdr.data(),
    c.phdr.size(),
    payload_span.data(),
    payload_span.size(),
    c.sig.data(),
    c.sig.size(),
    verify_err);
  CHECK(vrc != 0);
  CHECK(verify_err.is_set());
  CHECK(
    verify_err.to_string() ==
    "Algorithm mismatch between supplied alg and key");
}

TEST_CASE("CoseBuffer RAII semantics")
{
  SUBCASE("default construction")
  {
    CoseBuffer buf;
    CHECK(!buf.is_set());
    CHECK(buf.to_vector().empty());
  }

  SUBCASE("move construction")
  {
    TestKey key;
    CoseBuffer key_err;
    auto cose_key =
      CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
    REQUIRE(cose_key.is_set());
    const std::string epoch_begin = "1.1";
    const std::vector<uint8_t> payload = {1};

    CoseBuffer buf;
    CoseBuffer sign_err;
    cose_sign_endorsement(
      cose_key,
      0,
      reinterpret_cast<const uint8_t*>(epoch_begin.data()),
      epoch_begin.size(),
      nullptr,
      0,
      nullptr,
      0,
      payload.data(),
      payload.size(),
      buf,
      sign_err);
    REQUIRE(buf.is_set());

    auto vec_before = buf.to_vector();
    CoseBuffer moved(std::move(buf));
    CHECK(!buf.is_set());
    CHECK(moved.is_set());
    CHECK(moved.to_vector() == vec_before);
  }

  SUBCASE("reset")
  {
    TestKey key;
    CoseBuffer key_err;
    auto cose_key =
      CoseKey::from_private(key.priv_der.data(), key.priv_der.size(), key_err);
    REQUIRE(cose_key.is_set());
    const std::string epoch_begin = "1.1";
    const std::vector<uint8_t> payload = {1};

    CoseBuffer buf;
    CoseBuffer sign_err;
    cose_sign_endorsement(
      cose_key,
      0,
      reinterpret_cast<const uint8_t*>(epoch_begin.data()),
      epoch_begin.size(),
      nullptr,
      0,
      nullptr,
      0,
      payload.data(),
      payload.size(),
      buf,
      sign_err);
    REQUIRE(buf.is_set());

    buf.reset();
    CHECK(!buf.is_set());
  }
}

TEST_CASE("cose_free with null is safe")
{
  cose_free(nullptr, 0);
  cose_free(nullptr, 100);
}

TEST_CASE("CoseKey::from_pem_public")
{
  TestKey tk;
  auto pem = tk.kp.public_key_pem();

  SUBCASE("valid PEM succeeds")
  {
    CoseBuffer err;
    auto key = CoseKey::from_pem_public(pem.data(), pem.size(), err);
    CHECK(key.is_set());
    CHECK(!err.is_set());
  }

  SUBCASE("garbage fails with error")
  {
    const std::vector<uint8_t> garbage = {0xDE, 0xAD};
    CoseBuffer err;
    auto key = CoseKey::from_pem_public(garbage.data(), garbage.size(), err);
    CHECK(!key.is_set());
    CHECK(err.is_set());
  }
}

TEST_CASE("CoseKey::from_pem_cert")
{
  TestKey tk;
  auto cert_pem =
    tk.kp.self_sign("CN=test", "20200101000000Z", "20301231235959Z");

  SUBCASE("valid PEM cert succeeds and can verify")
  {
    CoseBuffer err;
    auto key = CoseKey::from_pem_cert(cert_pem.data(), cert_pem.size(), err);
    CHECK(key.is_set());
    CHECK(!err.is_set());

    // Sign with the private key, verify with the cert-derived key.
    CoseBuffer key_err;
    auto sign_key =
      CoseKey::from_private(tk.priv_der.data(), tk.priv_der.size(), key_err);
    REQUIRE(sign_key.is_set());

    const std::string epoch_begin = "1.1";
    const std::vector<uint8_t> payload = {0xCA, 0xFE};
    CoseBuffer out, sign_err;
    auto rc = cose_sign_endorsement(
      sign_key,
      0,
      reinterpret_cast<const uint8_t*>(epoch_begin.data()),
      epoch_begin.size(),
      nullptr,
      0,
      nullptr,
      0,
      payload.data(),
      payload.size(),
      out,
      sign_err);
    REQUIRE(rc == 0);
    REQUIRE(out.is_set());

    auto envelope = out.to_vector();
    auto c = decompose(envelope);
    CoseBuffer verify_err;
    auto vrc = cose_verify1(
      key,
      c.alg,
      c.phdr.data(),
      c.phdr.size(),
      c.payload.value().data(),
      c.payload.value().size(),
      c.sig.data(),
      c.sig.size(),
      verify_err);
    CHECK(vrc == 0);
  }

  SUBCASE("garbage fails with error")
  {
    const std::vector<uint8_t> garbage = {0xDE, 0xAD};
    CoseBuffer err;
    auto key = CoseKey::from_pem_cert(garbage.data(), garbage.size(), err);
    CHECK(!key.is_set());
    CHECK(err.is_set());
  }
}

TEST_CASE("CoseKey::from_der_cert")
{
  TestKey tk;
  auto cert_pem =
    tk.kp.self_sign("CN=test", "20200101000000Z", "20301231235959Z");
  // Convert PEM cert to DER via the raw bytes of the PEM -> parse -> re-encode.
  auto cert_der = ccf::crypto::cert_pem_to_der(cert_pem);

  SUBCASE("valid DER cert succeeds and can verify")
  {
    CoseBuffer err;
    auto key = CoseKey::from_der_cert(cert_der.data(), cert_der.size(), err);
    CHECK(key.is_set());
    CHECK(!err.is_set());

    // Sign with the private key, verify with the cert-derived key.
    CoseBuffer key_err;
    auto sign_key =
      CoseKey::from_private(tk.priv_der.data(), tk.priv_der.size(), key_err);
    REQUIRE(sign_key.is_set());

    const std::string epoch_begin = "1.1";
    const std::vector<uint8_t> payload = {0xCA, 0xFE};
    CoseBuffer out, sign_err;
    auto rc = cose_sign_endorsement(
      sign_key,
      0,
      reinterpret_cast<const uint8_t*>(epoch_begin.data()),
      epoch_begin.size(),
      nullptr,
      0,
      nullptr,
      0,
      payload.data(),
      payload.size(),
      out,
      sign_err);
    REQUIRE(rc == 0);
    REQUIRE(out.is_set());

    auto envelope = out.to_vector();
    auto c = decompose(envelope);
    CoseBuffer verify_err;
    auto vrc = cose_verify1(
      key,
      c.alg,
      c.phdr.data(),
      c.phdr.size(),
      c.payload.value().data(),
      c.payload.value().size(),
      c.sig.data(),
      c.sig.size(),
      verify_err);
    CHECK(vrc == 0);
  }

  SUBCASE("garbage fails with error")
  {
    const std::vector<uint8_t> garbage = {0xDE, 0xAD};
    CoseBuffer err;
    auto key = CoseKey::from_der_cert(garbage.data(), garbage.size(), err);
    CHECK(!key.is_set());
    CHECK(err.is_set());
  }
}
