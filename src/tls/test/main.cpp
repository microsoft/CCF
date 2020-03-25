// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../25519.h"
#include "../base64.h"
#include "../key_pair.h"
#include "../verifier.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;

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

static constexpr tls::CurveImpl supported_curves[] = {
  tls::CurveImpl::secp384r1,
#ifdef MOD_MBEDTLS
  tls::CurveImpl::ed25519,
#endif
  tls::CurveImpl::secp256k1_mbedtls,
  tls::CurveImpl::secp256k1_bitcoin};

static constexpr char const* labels[] = {"secp384r1",
#ifdef MOD_MBEDTLS
                                         "ed25519",
#endif
                                         "secp256k1_mbedtls",
                                         "secp256k1_bitcoin"};

TEST_CASE("Sign, verify, with KeyPair")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);
    CHECK(kp->verify(contents, signature));

    auto kp2 = tls::make_key_pair(kp->private_key_pem());
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
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = tls::make_public_key(public_key);
    CHECK(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad signature")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = tls::make_public_key(public_key);
    corrupt(signature);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = tls::make_public_key(public_key);
    corrupt(contents);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on correct curve")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    auto kp2 = tls::make_key_pair(curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = tls::make_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on wrong curve")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto wrong_curve = curve == tls::CurveImpl::secp384r1 ?
      tls::CurveImpl::secp256k1_mbedtls :
      tls::CurveImpl::secp384r1;
    auto kp2 = tls::make_key_pair(wrong_curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = tls::make_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

using CurvePair = std::pair<tls::CurveImpl, tls::CurveImpl>;
std::vector<CurvePair> equivalent_curves{
  std::make_pair(
    tls::CurveImpl::secp256k1_mbedtls, tls::CurveImpl::secp256k1_bitcoin),
  std::make_pair(
    tls::CurveImpl::secp256k1_bitcoin, tls::CurveImpl::secp256k1_mbedtls)};

TEST_CASE("Sign, verify with alternate implementation")
{
  for (const auto& curves : equivalent_curves)
  {
    INFO("Sign impl: " << labels[static_cast<size_t>(curves.first) - 1]);
    INFO("Verify impl: " << labels[static_cast<size_t>(curves.second) - 1]);
    auto kp = tls::make_key_pair(curves.first);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = tls::make_public_key(
      public_key, curves.second == tls::CurveImpl::secp256k1_bitcoin);
    CHECK(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, verify with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = kp->self_sign("CN=name");
    auto verifier = tls::make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
  }
}

TEST_CASE("Sign, verify. Fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = kp->self_sign("CN=name");
    auto verifier = tls::make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
    corrupt(contents);
    CHECK_FALSE(verifier->verify(contents, signature));
  }
}

tls::HashBytes bad_manual_hash(const std::vector<uint8_t>& data)
{
  // secp256k1 requires 32-byte hashes, other curves don't care. So use 32 for
  // general hasher
  constexpr auto n = 32;
  tls::HashBytes hash(n);

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
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    tls::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    const auto public_key = kp->public_key_pem();
    auto pubk = tls::make_public_key(public_key);
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
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    tls::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    auto cert = kp->self_sign("CN=name");
    auto verifier = tls::make_verifier(cert);
    CHECK(verifier->verify_hash(hash, signature));
    corrupt(hash);
    CHECK_FALSE(verifier->verify(hash, signature));
  }
}

TEST_CASE("Recoverable signatures")
{
  auto kp = tls::KeyPair_k1Bitcoin(MBEDTLS_ECP_DP_SECP256K1);

  vector<uint8_t> contents(contents_.begin(), contents_.end());
  tls::HashBytes hash = bad_manual_hash(contents);

  auto signature = kp.sign_recoverable_hashed(hash);
  const auto target_pem = kp.public_key_pem().str();

  auto recovered = tls::PublicKey_k1Bitcoin::recover_key(signature, hash);

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
      auto r = tls::PublicKey_k1Bitcoin::recover_key(signature, hash2);
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
      auto r = tls::PublicKey_k1Bitcoin::recover_key(signature2, hash);
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
      auto r = tls::PublicKey_k1Bitcoin::recover_key(signature3, hash);
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

    const auto encoded = tls::b64_from_raw(raw.data(), raw.size());
    const auto decoded = tls::raw_from_b64(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("Parse public x25519 PEM")
{
  auto x25519_public_key_pem = std::string(
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VuAyEAUgaVkiQ9K8UO3qEYD3C34vJT/CwiCr3AWnVn/1QMTl0=\n"
    "-----END PUBLIC KEY-----\n");
  auto x25519_public_key =
    tls::raw_from_b64("UgaVkiQ9K8UO3qEYD3C34vJT/CwiCr3AWnVn/1QMTl0=");

  auto raw_key = tls::PublicX25519::parse(tls::Pem(x25519_public_key_pem));

  REQUIRE(
    raw_key ==
    std::vector<uint8_t>(x25519_public_key.begin(), x25519_public_key.end()));

  REQUIRE(tls::PublicX25519::write(raw_key).str() == x25519_public_key_pem);
}