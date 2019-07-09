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

#define TEMPLATE_CURVE_TYPES \
  tls::CurveParameters<tls::CurveImpl::secp384r1>, \
    tls::CurveParameters<tls::CurveImpl::curve25519>, \
    tls::CurveParameters<tls::CurveImpl::secp256k1_mbedtls>, \
    tls::CurveParameters<tls::CurveImpl::secp256k1_bitcoin>

TEST_CASE_TEMPLATE("Sign, verify, with PublicKey", CP, TEMPLATE_CURVE_TYPES)
{
  tls::KeyPair<CP::curve> kp;
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp.sign(contents);

  vector<uint8_t> public_key = kp.public_key();
  tls::PublicKey<CP::curve> pubk(public_key);
  REQUIRE(pubk.verify(
    contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE_TEMPLATE(
  "Sign, fail to verify with bad signature", CP, TEMPLATE_CURVE_TYPES)
{
  tls::KeyPair<CP::curve> kp;
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp.sign(contents);

  vector<uint8_t> public_key = kp.public_key();
  tls::PublicKey<CP::curve> pubk(public_key);
  corrupt(signature);
  REQUIRE_FALSE(pubk.verify(
    contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE_TEMPLATE(
  "Sign, fail to verify with bad contents", CP, TEMPLATE_CURVE_TYPES)
{
  tls::KeyPair<CP::curve> kp;
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp.sign(contents);

  vector<uint8_t> public_key = kp.public_key();
  tls::PublicKey<CP::curve> pubk(public_key);
  corrupt(contents);
  REQUIRE_FALSE(pubk.verify(
    contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE_TEMPLATE(
  "Sign, fail to verify with wrong curve", CP, TEMPLATE_CURVE_TYPES)
{
  tls::KeyPair<CP::curve> kp;
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp.sign(contents);

  vector<uint8_t> public_key = kp.public_key();
  const auto wrong_curve = CP::curve == tls::CurveImpl::secp384r1 ?
    tls::CurveImpl::curve25519 :
    tls::CurveImpl::secp384r1;
  tls::PublicKey<wrong_curve> pubk(public_key);
  REQUIRE_FALSE(pubk.verify(
    contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE_TEMPLATE("Sign, verify with certificate", CP, TEMPLATE_CURVE_TYPES)
{
  tls::KeyPair<CP::curve> kp;
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp.sign(contents);

  auto cert = kp.self_sign("CN=name");
  tls::Verifier<CP::curve> verifier(cert);
  REQUIRE(verifier.verify(contents, signature));
}

TEST_CASE_TEMPLATE(
  "Sign, verify. Fail to verify with bad contents", CP, TEMPLATE_CURVE_TYPES)
{
  tls::KeyPair<CP::curve> kp;
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp.sign(contents);

  auto cert = kp.self_sign("CN=name");
  tls::Verifier<CP::curve> verifier(cert);
  REQUIRE(verifier.verify(contents, signature));
  corrupt(contents);
  REQUIRE_FALSE(verifier.verify(contents, signature));
}
