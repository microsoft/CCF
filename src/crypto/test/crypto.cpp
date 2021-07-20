// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "crypto/entropy.h"
#include "crypto/key_pair.h"
#include "crypto/key_wrap.h"
#include "crypto/mbedtls/entropy.h"
#include "crypto/mbedtls/key_pair.h"
#include "crypto/mbedtls/rsa_key_pair.h"
#include "crypto/mbedtls/symmetric_key.h"
#include "crypto/mbedtls/verifier.h"
#include "crypto/openssl/key_pair.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "crypto/openssl/symmetric_key.h"
#include "crypto/openssl/verifier.h"
#include "crypto/rsa_key_pair.h"
#include "crypto/symmetric_key.h"
#include "crypto/verifier.h"
#include "tls/base64.h"

#include <chrono>
#include <cstring>
#include <doctest/doctest.h>

using namespace std;
using namespace tls;
using namespace crypto;

static const string contents_ =
  "Lorem ipsum dolor sit amet, consectetur adipiscing "
  "elit, sed do eiusmod tempor incididunt ut labore et"
  " dolore magna aliqua. Ut enim ad minim veniam, quis"
  " nostrud exercitation ullamco laboris nisi ut "
  "aliquip ex ea commodo consequat. Duis aute irure "
  "dolor in reprehenderit in voluptate velit esse "
  "cillum dolore eu fugiat nulla pariatur. Excepteur "
  "sint occaecat cupidatat non proident, sunt in culpa "
  "qui officia deserunt mollit anim id est laborum.";

vector<uint8_t> contents(contents_.begin(), contents_.end());

template <typename T>
void corrupt(T& buf)
{
  buf[1]++;
  buf[buf.size() / 2]++;
  buf[buf.size() - 2]++;
}

static constexpr CurveID supported_curves[] = {CurveID::SECP384R1,
                                               CurveID::SECP256R1};

static constexpr char const* labels[] = {"secp384r1", "secp256r1"};

TEST_CASE("Sign, verify, with KeyPair")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);
    CHECK(kp->verify(contents, signature));

    auto kp2 = make_key_pair(kp->private_key_pem());
    CHECK(kp2->verify(contents, signature));

    // Signatures won't necessarily be identical due to entropy, but should be
    // mutually verifiable
    for (auto i = 0; i < 10; ++i)
    {
      const auto new_sig = kp2->sign(contents);
      CHECK(kp->verify(contents, new_sig));
      CHECK(kp2->verify(contents, new_sig));
    }
  }
}

TEST_CASE("Sign, verify, with PublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad signature")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    corrupt(signature);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    corrupt(contents);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on correct curve")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    auto kp2 = make_key_pair(curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on wrong curve")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto wrong_curve =
      curve == CurveID::SECP384R1 ? CurveID::SECP256R1 : CurveID::SECP384R1;
    auto kp2 = make_key_pair(wrong_curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

template <typename T, typename S, CurveID CID>
void run_alt()
{
  T kp1(CID);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp1.sign(contents);

  S kp2(kp1.public_key_pem());
  CHECK(kp2.verify(contents, signature));
}

TEST_CASE("Sign, verify with alternate implementation")
{
  run_alt<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP256R1>();
  run_alt<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256R1>();
  run_alt<KeyPair_OpenSSL, PublicKey_mbedTLS, CurveID::SECP384R1>();
  run_alt<KeyPair_mbedTLS, PublicKey_OpenSSL, CurveID::SECP384R1>();
  run_alt<KeyPair_OpenSSL, PublicKey_mbedTLS, CurveID::SECP256R1>();
  run_alt<KeyPair_mbedTLS, PublicKey_OpenSSL, CurveID::SECP256R1>();
}

TEST_CASE("Sign, verify with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = kp->self_sign("CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
  }
}

TEST_CASE("Sign, verify. Fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = kp->self_sign("CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
    corrupt(contents);
    CHECK_FALSE(verifier->verify(contents, signature));
  }
}

crypto::HashBytes bad_manual_hash(const std::vector<uint8_t>& data)
{
  // secp256r1 requires 32-byte hashes, other curves don't care. So use 32 for
  // general hasher
  constexpr auto n = 32;
  crypto::HashBytes hash(n);

  for (size_t i = 0; i < data.size(); ++i)
  {
    hash[i % n] ^= data[i];
  }

  return hash;
}

TEST_CASE("Manually hash, sign, verify, with PublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    crypto::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK(pubk->verify_hash(hash, signature, MDType::SHA256));
    corrupt(hash);
    CHECK_FALSE(pubk->verify_hash(hash, signature, MDType::SHA256));
  }
}

TEST_CASE("Manually hash, sign, verify, with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    crypto::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    auto cert = kp->self_sign("CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify_hash(hash, signature));
    corrupt(hash);
    CHECK_FALSE(verifier->verify(hash, signature));
  }
}

TEST_CASE("base64")
{
  for (size_t length = 1; length < 20; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    const auto encoded = b64_from_raw(raw.data(), raw.size());
    const auto decoded = raw_from_b64(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("base64url")
{
  for (size_t length = 1; length < 20; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    auto encoded = b64_from_raw(raw.data(), raw.size());
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    encoded.erase(
      std::find(encoded.begin(), encoded.end(), '='), encoded.end());
    const auto decoded = raw_from_b64url(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("Wrap, unwrap with RSAKeyPair")
{
  size_t input_len = 64;
  std::vector<uint8_t> input = create_entropy()->random(input_len);

  INFO("Cannot make RSA key from EC key");
  {
    for (const auto curve : supported_curves)
    {
      auto rsa_kp = make_key_pair(curve); // EC Key

      REQUIRE_THROWS_AS(
        make_rsa_public_key(rsa_kp->public_key_pem()), std::logic_error);
    }
  }

  INFO("Without label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());

    // Public key can wrap
    auto wrapped = rsa_pub->rsa_oaep_wrap(input);

    // Only private key can unwrap
    auto unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped);
    // rsa_pub->unwrap(wrapped); // Doesn't compile
    REQUIRE(input == unwrapped);

    // Raw data
    wrapped = rsa_pub->rsa_oaep_wrap(input.data(), input.size());
    unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped);
    REQUIRE(input == unwrapped);
  }

  INFO("With label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());
    std::string lblstr = "my_label";
    std::vector<uint8_t> label(lblstr.begin(), lblstr.end());
    auto wrapped = rsa_pub->rsa_oaep_wrap(input, label);
    auto unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped, label);
    REQUIRE(input == unwrapped);
  }
}

TEST_CASE("RSA-OAEP mbedTLS vs OpenSSL")
{
  std::vector<uint8_t> input = create_entropy()->random(32);

  size_t key_sz = 2048;

  auto kp_mbed = std::make_shared<RSAKeyPair_mbedTLS>(key_sz);
  auto pk_mbed =
    std::make_shared<RSAPublicKey_mbedTLS>(kp_mbed->public_key_pem());

  auto kp_ossl =
    std::make_shared<RSAKeyPair_OpenSSL>(kp_mbed->private_key_pem());
  auto pk_ossl =
    std::make_shared<RSAPublicKey_OpenSSL>(pk_mbed->public_key_pem());

  INFO("mbedTLS -> OpenSSL");
  {
    auto wrapped = pk_mbed->rsa_oaep_wrap(input);
    REQUIRE(wrapped.size() == key_sz / 8);
    auto unwrapped = kp_ossl->rsa_oaep_unwrap(wrapped);
    REQUIRE(input == unwrapped);
  }

  INFO("OpenSSL -> mbedTLS");
  {
    auto wrapped = pk_ossl->rsa_oaep_wrap(input);
    REQUIRE(wrapped.size() == key_sz / 8);
    auto unwrapped = kp_mbed->rsa_oaep_unwrap(wrapped);
    REQUIRE(input == unwrapped);
  }
}

TEST_CASE("Extract public key from cert")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    auto pk = kp->public_key_der();
    auto cert = kp->self_sign("CN=name");
    auto cert_der = make_verifier(cert.raw())->cert_der();
    auto pubk = public_key_der_from_cert(cert_der);
    REQUIRE(pk == pubk);
  }
}

template <typename T, typename S>
void run_csr()
{
  T kpm(CurveID::SECP384R1);

  const char* subject_name = "CN=myname";

  std::vector<SubjectAltName> subject_alternative_names;

  // mbedtls doesn't support parsing SAN from CSR
  if constexpr (std::is_same_v<T, KeyPair_OpenSSL>)
  {
    subject_alternative_names.push_back({"email:my-other-name", false});
    subject_alternative_names.push_back({"www.microsoft.com", false});
    subject_alternative_names.push_back({"192.168.0.1", true});
  }

  auto csr = kpm.create_csr(subject_name, subject_alternative_names);

  auto icrt = kpm.self_sign("CN=issuer");
  auto crt = kpm.sign_csr(icrt, csr);

  std::vector<uint8_t> content = {0, 1, 2, 3, 4};
  auto signature = kpm.sign(content);

  S v(crt.raw());
  REQUIRE(v.verify(content, signature));
}

TEST_CASE("Create, sign & verify certificates")
{
  run_csr<KeyPair_mbedTLS, Verifier_mbedTLS>();
  run_csr<KeyPair_mbedTLS, Verifier_OpenSSL>();
  run_csr<KeyPair_OpenSSL, Verifier_mbedTLS>();
  run_csr<KeyPair_OpenSSL, Verifier_OpenSSL>();
}

static const vector<uint8_t>& getRawKey()
{
  static const vector<uint8_t> v(16, '$');
  return v;
}

TEST_CASE("ExtendedIv0")
{
  auto k = crypto::make_key_aes_gcm(getRawKey());
  // setup plain text
  unsigned char rawP[100];
  memset(rawP, 'x', sizeof(rawP));
  Buffer p{rawP, sizeof(rawP)};
  // test large IV
  GcmHeader<1234> h;
  k->encrypt(h.get_iv(), p, nullb, p.p, h.tag);

  auto k2 = crypto::make_key_aes_gcm(getRawKey());
  REQUIRE(k2->decrypt(h.get_iv(), h.tag, p, nullb, p.p));
}

TEST_CASE("AES mbedTLS vs OpenSSL")
{
  auto key = getRawKey();

  GcmHeader<1234> h;

  { // mbedTLS -> OpenSSL
    auto mbed = std::make_unique<KeyAesGcm_mbedTLS>(key);
    auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

    std::vector<uint8_t> encrypted(contents_.size());
    mbed->encrypt(h.get_iv(), contents_, nullb, encrypted.data(), h.tag);

    std::vector<unsigned char> rawP(contents_.size(), 'x');
    Buffer p{rawP.data(), rawP.size()};

    std::vector<uint8_t> decrypted(contents_.size());
    REQUIRE(ossl->decrypt(
      h.get_iv(),
      h.tag,
      {encrypted.data(), encrypted.size()},
      nullb,
      decrypted.data()));

    REQUIRE(decrypted == contents);
  }

  { // OpenSSL -> mbedTLS
    auto mbed = std::make_unique<KeyAesGcm_mbedTLS>(key);
    auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

    std::vector<uint8_t> encrypted(contents_.size());
    ossl->encrypt(h.get_iv(), contents_, nullb, encrypted.data(), h.tag);

    std::vector<unsigned char> rawP(contents_.size(), 'x');
    Buffer p{rawP.data(), rawP.size()};

    std::vector<uint8_t> decrypted(contents_.size());
    CBuffer encbuf{encrypted.data(), encrypted.size()};
    REQUIRE(mbed->decrypt(h.get_iv(), h.tag, encbuf, nullb, decrypted.data()));

    REQUIRE(decrypted == contents);
  }
}

TEST_CASE("AES mbedTLS vs OpenSSL + AAD")
{
  auto key = getRawKey();

  GcmHeader<1234> h;
  std::vector<uint8_t> aad(123, 'y');

  {
    INFO("mbedTLS -> OpenSSL");

    auto mbed = std::make_unique<KeyAesGcm_mbedTLS>(key);
    auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

    std::vector<uint8_t> encrypted(contents_.size());
    mbed->encrypt(h.get_iv(), contents_, aad, encrypted.data(), h.tag);

    std::vector<unsigned char> rawP(contents_.size(), 'x');
    Buffer p{rawP.data(), rawP.size()};

    std::vector<uint8_t> decrypted(contents_.size());
    REQUIRE(ossl->decrypt(
      h.get_iv(),
      h.tag,
      {encrypted.data(), encrypted.size()},
      aad,
      decrypted.data()));

    REQUIRE(decrypted == contents);
  }

  {
    INFO("OpenSSL -> mbedTLS");

    auto mbed = std::make_unique<KeyAesGcm_mbedTLS>(key);
    auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

    std::vector<uint8_t> encrypted(contents_.size());
    ossl->encrypt(h.get_iv(), contents_, aad, encrypted.data(), h.tag);

    std::vector<unsigned char> rawP(contents_.size(), 'x');
    Buffer p{rawP.data(), rawP.size()};

    std::vector<uint8_t> decrypted(contents_.size());
    CBuffer encbuf{encrypted.data(), encrypted.size()};
    REQUIRE(mbed->decrypt(h.get_iv(), h.tag, encbuf, aad, decrypted.data()));

    REQUIRE(decrypted == contents);
  }
}

TEST_CASE("AES Key wrap with padding")
{
  auto key = getRawKey();
  GcmHeader<1234> h;
  std::vector<uint8_t> aad(123, 'y');

  std::vector<uint8_t> key_to_wrap = create_entropy()->random(997);

  auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

  std::vector<uint8_t> wrapped = ossl->ckm_aes_key_wrap_pad(key_to_wrap);
  std::vector<uint8_t> unwrapped = ossl->ckm_aes_key_unwrap_pad(wrapped);

  REQUIRE(wrapped != unwrapped);
  REQUIRE(key_to_wrap == unwrapped);
}

TEST_CASE("CKM_RSA_PKCS_OAEP")
{
  auto key = getRawKey();

  auto rsa_kp = make_rsa_key_pair();
  auto rsa_pk = make_rsa_public_key(rsa_kp->public_key_pem());

  auto wrapped = crypto::ckm_rsa_pkcs_oaep_wrap(rsa_pk, key);
  auto wrapped_ = crypto::ckm_rsa_pkcs_oaep_wrap(rsa_pk, key);

  // CKM_RSA_PKCS_OAEP wrap is non deterministic
  REQUIRE(wrapped != wrapped_);

  auto unwrapped = crypto::ckm_rsa_pkcs_oaep_unwrap(rsa_kp, wrapped);
  auto unwrapped_ = crypto::ckm_rsa_pkcs_oaep_unwrap(rsa_kp, wrapped_);

  REQUIRE(unwrapped == unwrapped_);
}

TEST_CASE("CKM_RSA_AES_KEY_WRAP")
{
  std::vector<uint8_t> key_to_wrap = create_entropy()->random(256);

  auto rsa_kp = make_rsa_key_pair();
  auto rsa_pk = make_rsa_public_key(rsa_kp->public_key_pem());

  std::vector<uint8_t> wrapped = ckm_rsa_aes_key_wrap(128, rsa_pk, key_to_wrap);
  std::vector<uint8_t> unwrapped = ckm_rsa_aes_key_unwrap(rsa_kp, wrapped);

  REQUIRE(wrapped != unwrapped);
  REQUIRE(unwrapped == key_to_wrap);
}

TEST_CASE("AES-GCM convenience functions")
{
  EntropyPtr entropy = create_entropy();
  std::vector<uint8_t> key = entropy->random(GCM_SIZE_KEY);
  auto encrypted = aes_gcm_encrypt(key, contents);
  auto decrypted = aes_gcm_decrypt(key, encrypted);
  REQUIRE(decrypted == contents);
}