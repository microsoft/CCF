// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../keypair.h"

#include <doctest/doctest.h>
#include <chrono>
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
  buf[buf.size() / 2]++;
}

TEST_CASE("Sign, verify, with PublicKey")
{
    tls::KeyPair kp;
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp.sign(contents);

    vector<uint8_t> public_key = kp.public_key();
    tls::PublicKey pubk(public_key);
    REQUIRE(pubk.verify(contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE("Sign, fail to verify with bad signature")
{
    tls::KeyPair kp;
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp.sign(contents);

    vector<uint8_t> public_key = kp.public_key();
    tls::PublicKey pubk(public_key);
    corrupt(signature);
    REQUIRE_FALSE(pubk.verify(contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE("Sign, fail to verify with bad contents")
{
    tls::KeyPair kp;
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp.sign(contents);

    vector<uint8_t> public_key = kp.public_key();
    tls::PublicKey pubk(public_key);
    corrupt(contents);
    REQUIRE_FALSE(pubk.verify(contents.data(), contents.size(), signature.data(), signature.size()));
}

TEST_CASE("Sign, verify with certificate")
{
    tls::KeyPair kp;
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp.sign(contents);

    auto cert = kp.self_sign("CN=name");
    tls::Verifier verifier(cert);
    REQUIRE(verifier.verify(contents, signature));
}


TEST_CASE("Sign, verify. Fail to verify with bad contents")
{
    tls::KeyPair kp;
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp.sign(contents);

    auto cert = kp.self_sign("CN=name");
    tls::Verifier verifier(cert);
    REQUIRE(verifier.verify(contents, signature));
    corrupt(contents);
    REQUIRE_FALSE(verifier.verify(contents, signature));
}
