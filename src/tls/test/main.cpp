// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../keypair.h"

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

void corrupt(std::vector<uint8_t>& buf)
{
  buf[1]++;
  buf[buf.size() / 2]++;
  buf[buf.size() - 2]++;
}

static constexpr tls::CurveImpl supported_curves[] = {
  tls::CurveImpl::secp384r1,
  tls::CurveImpl::curve25519,
  tls::CurveImpl::secp256k1_mbedtls,
  tls::CurveImpl::secp256k1_bitcoin};

static constexpr char const* labels[] = {
  "secp384r1", "curve25519", "secp256k1_mbedtls", "secp256k1_bitcoin"};

TEST_CASE("Sign, verify, with PublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    vector<uint8_t> public_key = kp->public_key();
    auto pubk = tls::make_public_key(public_key);
    REQUIRE(pubk->verify(contents, signature));
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

    vector<uint8_t> public_key = kp->public_key();
    auto pubk = tls::make_public_key(public_key);
    corrupt(signature);
    REQUIRE_FALSE(pubk->verify(contents, signature));
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

    vector<uint8_t> public_key = kp->public_key();
    auto pubk = tls::make_public_key(public_key);
    corrupt(contents);
    REQUIRE_FALSE(pubk->verify(contents, signature));
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
    vector<uint8_t> public_key = kp2->public_key();
    auto pubk = tls::make_public_key(public_key);
    REQUIRE_FALSE(pubk->verify(contents, signature));
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
      tls::CurveImpl::curve25519 :
      tls::CurveImpl::secp384r1;
    auto kp2 = tls::make_key_pair(wrong_curve);
    vector<uint8_t> public_key = kp2->public_key();
    auto pubk = tls::make_public_key(public_key);
    REQUIRE_FALSE(pubk->verify(contents, signature));
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

    vector<uint8_t> public_key = kp->public_key();
    auto pubk = tls::make_public_key(
      public_key, curves.second == tls::CurveImpl::secp256k1_bitcoin);
    REQUIRE(pubk->verify(contents, signature));
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
    REQUIRE(verifier->verify(contents, signature));
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
    REQUIRE(verifier->verify(contents, signature));
    corrupt(contents);
    REQUIRE_FALSE(verifier->verify(contents, signature));
  }
}

TEST_CASE("Manually hash, sign, verify, with PublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    tls::HashBytes hash;
    tls::do_hash(kp->get_raw_context(), contents.data(), contents.size(), hash);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    vector<uint8_t> public_key = kp->public_key();
    auto pubk = tls::make_public_key(public_key);
    REQUIRE(pubk->verify_hash(hash, signature));
    corrupt(hash);
    REQUIRE_FALSE(pubk->verify_hash(hash, signature));
  }
}

TEST_CASE("Manually hash, sign, verify, with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = tls::make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    tls::HashBytes hash;
    tls::do_hash(kp->get_raw_context(), contents.data(), contents.size(), hash);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    auto cert = kp->self_sign("CN=name");
    auto verifier = tls::make_verifier(cert);
    REQUIRE(verifier->verify_hash(hash, signature));
    corrupt(hash);
    REQUIRE_FALSE(verifier->verify(hash, signature));
  }
}
