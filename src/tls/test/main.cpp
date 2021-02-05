// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "tls/base64.h"
#include "tls/key_pair.h"
#include "tls/rsa_key_pair.h"
#include "tls/verifier.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;
using namespace tls;

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

template <typename T>
void corrupt(T& buf)
{
  buf[1]++;
  buf[buf.size() / 2]++;
  buf[buf.size() - 2]++;
}

static constexpr CurveID supported_curves[] = {
  CurveID::SECP384R1, CurveID::SECP256K1, CurveID::SECP256R1};

static constexpr char const* labels[] = {"secp384r1", "secp256k1", "secp256r1"};

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
      curve == CurveID::SECP384R1 ? CurveID::SECP256K1 : CurveID::SECP384R1;
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
  run_alt<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP256K1>();
  run_alt<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256K1>();
  run_alt<KeyPair_k1Bitcoin, PublicKey_k1Bitcoin, CurveID::SECP256K1>();

  run_alt<KeyPair_mbedTLS, PublicKey_k1Bitcoin, CurveID::SECP256K1>();
  run_alt<KeyPair_mbedTLS, PublicKey_OpenSSL, CurveID::SECP256K1>();

  run_alt<KeyPair_k1Bitcoin, PublicKey_mbedTLS, CurveID::SECP256K1>();
  run_alt<KeyPair_k1Bitcoin, PublicKey_OpenSSL, CurveID::SECP256K1>();

  run_alt<KeyPair_OpenSSL, PublicKey_mbedTLS, CurveID::SECP256K1>();
  run_alt<KeyPair_OpenSSL, PublicKey_k1Bitcoin, CurveID::SECP256K1>();

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
  // secp256k1 requires 32-byte hashes, other curves don't care. So use 32 for
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
    CHECK(pubk->verify_hash(hash, signature));
    corrupt(hash);
    CHECK_FALSE(pubk->verify_hash(hash, signature));
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

TEST_CASE("Recoverable signatures")
{
  auto kp = KeyPair_k1Bitcoin(CurveID::SECP256K1);

  vector<uint8_t> contents(contents_.begin(), contents_.end());
  crypto::HashBytes hash = bad_manual_hash(contents);

  auto signature = kp.sign_recoverable_hashed(hash);
  const auto target_pem = kp.public_key_pem().str();

  auto recovered = PublicKey_k1Bitcoin::recover_key(signature, hash);

  {
    INFO("Normal recovery");
    CHECK(target_pem == recovered.public_key_pem().str());
  }

  // NB: Incorrect arguments _may_ cause the verification to throw with no
  // recoverable key, but they may simply cause a different key to be returned.
  // These tests look for either type of failure.

  {
    INFO("Corrupted hash");
    auto hash2(hash);
    corrupt(hash2);
    bool recovery_failed = false;
    try
    {
      auto r = PublicKey_k1Bitcoin::recover_key(signature, hash2);
      recovery_failed = target_pem != r.public_key_pem().str();
    }
    catch (const std::exception& e)
    {
      recovery_failed = true;
    }
    CHECK(recovery_failed);
  }

  {
    INFO("Corrupted signature");
    auto signature2(signature);
    corrupt(signature2.raw);
    bool recovery_failed = false;
    try
    {
      auto r = PublicKey_k1Bitcoin::recover_key(signature2, hash);
      recovery_failed = target_pem != r.public_key_pem().str();
    }
    catch (const std::exception& e)
    {
      recovery_failed = true;
    }
    CHECK(recovery_failed);
  }

  {
    INFO("Corrupted recovery_id");
    auto signature3(signature);
    signature3.recovery_id = (signature3.recovery_id + 1) % 4;
    bool recovery_failed = false;
    try
    {
      auto r = PublicKey_k1Bitcoin::recover_key(signature3, hash);
      recovery_failed = target_pem != r.public_key_pem().str();
    }
    catch (const std::exception& e)
    {
      recovery_failed = true;
    }
    CHECK(recovery_failed);
  }

  {
    INFO("Recovered key is useable");

    auto norm_sig = kp.sign(contents);
    CHECK(recovered.verify(contents, norm_sig));
    corrupt(norm_sig);
    CHECK_FALSE(recovered.verify(contents, norm_sig));
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
    auto rsa_kp = make_key_pair(); // EC Key

    REQUIRE_THROWS_AS(
      make_rsa_public_key(rsa_kp->public_key_pem()), std::logic_error);
  }

  INFO("Without label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());

    // Public key can wrap
    auto wrapped = rsa_pub->wrap(input);

    // Only private key can unwrap
    auto unwrapped = rsa_kp->unwrap(wrapped);
    // rsa_pub->unwrap(wrapped); // Doesn't compile
    REQUIRE(input == unwrapped);

    // Raw data
    wrapped = rsa_pub->wrap(input.data(), input.size());
    unwrapped = rsa_kp->unwrap(wrapped);
    REQUIRE(input == unwrapped);
  }

  INFO("With label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());
    std::string label = "my_label";
    auto wrapped = rsa_pub->wrap(input, label);
    auto unwrapped = rsa_kp->unwrap(wrapped, label);
    REQUIRE(input == unwrapped);
  }
}

TEST_CASE("Extract public key from cert")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    auto pk = kp->public_key_pem();
    auto cert = kp->self_sign("CN=name");

    auto pubk = public_key_pem_from_cert(cert);
    REQUIRE(pk == pubk);
  }
}

template <typename T, typename S>
void run_csr()
{
  T kpm(CurveID::SECP384R1);

  const char* subject_name = "CN=myname";

  auto csr = kpm.create_csr(subject_name);

  std::vector<SubjectAltName> subject_alternative_names;
  subject_alternative_names.push_back({"email:my-other-name", false});
  subject_alternative_names.push_back({"DNS:www.microsoft.com", false});
  // subject_alternative_names.push_back({"IP:192.168.0.1", true}); // mbedTLS
  // doesn't like IPs?
  auto crt = kpm.sign_csr(csr, "CN=issuer", subject_alternative_names);

  std::vector<uint8_t> content = {0, 1, 2, 3, 4};
  auto signature = kpm.sign(content);

  S v(crt.raw());
  REQUIRE(v.verify(content, signature));
}

TEST_CASE("Create, sign & verify certificates")
{
  run_csr<KeyPair_mbedTLS, Verifier_MBedTLS>();
  run_csr<KeyPair_mbedTLS, Verifier_OpenSSL>();
  run_csr<KeyPair_OpenSSL, Verifier_MBedTLS>();
  run_csr<KeyPair_OpenSSL, Verifier_OpenSSL>();
}