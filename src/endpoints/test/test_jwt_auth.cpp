// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/crypto/base64.h"
#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/ecdsa.h"
#include "ccf/endpoints/authentication/jwt_auth.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "node/rpc/http_rpc_context.h"
#include "node/rpc/jwt_management.h"

#include <array>
#include <barrier>
#include <doctest/doctest.h>
#include <thread>

using namespace ccf;

namespace
{
  class TestJwtAuthnPolicy : public JwtAuthnPolicy
  {
  public:
    const void* cache_address() const
    {
      return keys_cache.get();
    }
  };

  std::shared_ptr<RpcContext> make_jwt_request(
    const crypto::ECKeyPairPtr& key, bool valid = true)
  {
    const std::string header = R"({"alg":"ES256","kid":"test-key"})";
    const auto expiry = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count() +
      3600;
    const auto payload =
      nlohmann::json{{"iss", "https://issuer.example"}, {"exp", expiry}}.dump();
    const auto encode = [](const std::string& s) {
      return crypto::b64url_from_raw(
        reinterpret_cast<const uint8_t*>(s.data()), s.size(), false);
    };
    const auto content = encode(header) + "." + encode(payload);
    auto signature = crypto::ecdsa_sig_der_to_p1363(
      key->sign(
        {reinterpret_cast<const uint8_t*>(content.data()), content.size()},
        crypto::MDType::SHA256),
      crypto::CurveID::SECP256R1);
    if (!valid)
    {
      signature[0] ^= 1;
    }
    return std::make_shared<::http::HttpRpcContext>(
      std::make_shared<SessionContext>(0, std::vector<uint8_t>{}),
      HttpVersion::HTTP1,
      HTTP_GET,
      "/",
      ccf::http::HeaderMap{
        {ccf::http::headers::AUTHORIZATION,
         "Bearer " + content + "." +
           crypto::b64url_from_raw(signature, false)}},
      std::vector<uint8_t>{});
  }

  void set_signing_key(kv::Store& store, const crypto::ECKeyPairPtr& key)
  {
    store.set_encryptor(std::make_shared<kv::NullTxEncryptor>());
    auto tx = store.create_tx();
    tx.rw<JwtPublicSigningKeysMetadata>(
        Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA)
      ->put(
        "test-key",
        {{key->public_key_der(), "https://issuer.example", std::nullopt}});
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }
}

TEST_CASE("JWT key cache is local to each thread")
{
  TestJwtAuthnPolicy policy;
  constexpr size_t worker_count = 4;
  std::array<const void*, worker_count> addresses{};
  std::barrier ready(worker_count + 1);
  std::vector<std::jthread> workers;
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&, i] {
      addresses[i] = policy.cache_address();
      ready.arrive_and_wait();
      ready.arrive_and_wait();
    });
  }
  ready.arrive_and_wait();
  for (size_t i = 0; i < worker_count; ++i)
  {
    CHECK(addresses[i] != nullptr);
    CHECK(addresses[i] != policy.cache_address());
    for (size_t j = 0; j < i; ++j)
    {
      CHECK(addresses[i] != addresses[j]);
    }
  }
  ready.arrive_and_wait();
}

TEST_CASE("Shared JWT policy verifies signatures and observes key rotation")
{
  JwtAuthnPolicy policy;
  const auto key = crypto::make_ec_key_pair(crypto::CurveID::SECP256R1);
  const auto replacement = crypto::make_ec_key_pair(crypto::CurveID::SECP256R1);
  const auto valid_request = make_jwt_request(key);
  const auto invalid_request = make_jwt_request(key, false);
  const auto replacement_request = make_jwt_request(replacement);
  constexpr size_t worker_count = 4;
  std::array<kv::Store, worker_count> stores;
  for (auto& store : stores)
  {
    set_signing_key(store, key);
  }

  std::barrier phase(worker_count + 1);
  std::vector<std::jthread> workers;
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&, i] {
      for (bool rotated : {false, true})
      {
        phase.arrive_and_wait();
        for (size_t n = 0; n < 16; ++n)
        {
          auto tx = stores[i].create_read_only_tx();
          std::string reason;
          CHECK(
            (policy.authenticate(tx, valid_request, reason) != nullptr) ==
            !rotated);
          CHECK(policy.authenticate(tx, invalid_request, reason) == nullptr);
          CHECK(reason == "Signature verification failed");
          CHECK(
            (policy.authenticate(tx, replacement_request, reason) != nullptr) ==
            rotated);
        }
        phase.arrive_and_wait();
      }
    });
  }
  phase.arrive_and_wait();
  phase.arrive_and_wait();
  for (auto& store : stores)
  {
    set_signing_key(store, replacement);
  }
  phase.arrive_and_wait();
  phase.arrive_and_wait();
}

TEST_CASE("Validate JWT issuer")
{
  REQUIRE_FALSE(validate_issuer("https://example.issuer", std::nullopt, ""));
  REQUIRE_FALSE(
    validate_issuer("https://example.issuer", "", "https://example.issuer"));
  REQUIRE_FALSE(validate_issuer(
    "https://example.issuer",
    "https://example.issuer",
    "https://example.issuer"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/{tenantid}/v2.0",
    "deadbeef",
    "https://login.microsoftonline.com/deadbeef/v2.0"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0",
    std::nullopt,
    "https://login.microsoftonline.com/deadbeef/v2.0"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0",
    "",
    "https://login.microsoftonline.com/deadbeef/v2.0"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0", "deadbeef", ""));

  REQUIRE(validate_issuer(
    "https://example.issuer", std::nullopt, "https://example.issuer"));
  REQUIRE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0",
    "deadbeef",
    "https://login.microsoftonline.com/deadbeef/v2.0"));
}

TEST_CASE("Check JWT issuer constraint")
{
  REQUIRE_FALSE(check_issuer_constraint("", ""));
  REQUIRE_FALSE(check_issuer_constraint("https://issuer.com", ""));
  REQUIRE_FALSE(check_issuer_constraint("", "https://issuer.com"));
  REQUIRE_FALSE(check_issuer_constraint(
    "https://issuer.com", "https://issuer.another.com"));
  REQUIRE_FALSE(check_issuer_constraint(
    "https://issuer.com", "https://subdomain.issuer.com"));

  REQUIRE(check_issuer_constraint("https://issuer.com", "https://issuer.com"));
  REQUIRE(
    check_issuer_constraint("https://issuer.com/path", "https://issuer.com"));
  REQUIRE(check_issuer_constraint(
    "https://issuer.com/path", "https://issuer.com/more-path"));
  REQUIRE(check_issuer_constraint(
    "https://subdomain.issuer.com", "https://issuer.com"));
  REQUIRE(check_issuer_constraint(
    "https://subdomain.issuer.com/more/paths", "https://issuer.com"));
  REQUIRE(check_issuer_constraint(
    "https://subdomain.issuer.com", "https://issuer.com/path"));
  REQUIRE(check_issuer_constraint(
    "https://subdomain.issuer.com/more/paths",
    "https://issuer.com/even/more/paths"));
}