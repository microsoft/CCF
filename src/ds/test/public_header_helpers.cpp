// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/base_endpoint_registry.h"
#include "ccf/claims_digest.h"
#include "ccf/crypto/curve.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/san.h"
#include "ccf/ds/locking.h"
#include "ccf/http_status.h"
#include "ccf/rest_verb.h"
#include "ccf/service/tables/proposals.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <array>
#include <atomic>
#include <doctest/doctest.h>
#include <limits>
#include <span>
#include <thread>

TEST_CASE("API result strings")
{
  constexpr std::array api_results = {
    std::pair{ccf::ApiResult::OK, "OK"},
    std::pair{ccf::ApiResult::Uninitialised, "Uninitialised"},
    std::pair{ccf::ApiResult::InvalidArgs, "InvalidArgs"},
    std::pair{ccf::ApiResult::NotFound, "NotFound"},
    std::pair{ccf::ApiResult::InternalError, "InternalError"}};
  for (const auto& [result, expected] : api_results)
  {
    CHECK(ccf::api_result_to_str(result) == std::string_view(expected));
  }
  CHECK(
    ccf::api_result_to_str(static_cast<ccf::ApiResult>(255)) ==
    std::string_view("Unhandled ApiResult"));

  constexpr std::array invalid_args_reasons = {
    std::pair{ccf::InvalidArgsReason::NoReason, "NoReason"},
    std::pair{ccf::InvalidArgsReason::ViewSmallerThanOne, "ViewSmallerThanOne"},
    std::pair{
      ccf::InvalidArgsReason::ActionAlreadyApplied, "ActionAlreadyApplied"},
    std::pair{
      ccf::InvalidArgsReason::StaleActionCreatedTimestamp,
      "StaleActionCreatedTimestamp"}};
  for (const auto& [reason, expected] : invalid_args_reasons)
  {
    CHECK(
      ccf::invalid_args_reason_to_str(reason) == std::string_view(expected));
  }
  CHECK(
    ccf::invalid_args_reason_to_str(static_cast<ccf::InvalidArgsReason>(255)) ==
    std::string_view("Unhandled InvalidArgsReason"));
}

TEST_CASE("REST verbs")
{
  CHECK(ccf::http_method_from_str("GET") == HTTP_GET);
  CHECK(ccf::http_method_from_str("POST") == HTTP_POST);
  CHECK_THROWS_AS(ccf::http_method_from_str("UNKNOWN"), std::logic_error);

  const ccf::RESTVerb get_from_method = HTTP_GET;
  const ccf::RESTVerb get_from_string = std::string("GET");
  const ccf::RESTVerb post = HTTP_POST;
  CHECK(get_from_method.get_http_method() == HTTP_GET);
  CHECK(std::string_view(get_from_method.c_str()) == "GET");
  CHECK(get_from_method == get_from_string);
  CHECK(get_from_method != post);
  CHECK(
    (get_from_method < post) ==
    (static_cast<int>(HTTP_GET) < static_cast<int>(HTTP_POST)));

  nlohmann::json json = post;
  CHECK(json == "post");
  CHECK(json.get<ccf::RESTVerb>() == post);
  CHECK(nlohmann::json("get").get<ccf::RESTVerb>() == get_from_method);
  CHECK_THROWS_AS(nlohmann::json(42).get<ccf::RESTVerb>(), std::runtime_error);
  CHECK_THROWS_AS(
    nlohmann::json("unknown").get<ccf::RESTVerb>(), std::logic_error);

  CHECK(
    ccf::schema_name(static_cast<const ccf::RESTVerb*>(nullptr)) ==
    "HttpMethod");
  nlohmann::json schema;
  ccf::fill_json_schema(schema, static_cast<const ccf::RESTVerb*>(nullptr));
  CHECK(schema == nlohmann::json{{"type", "string"}});
}

TEST_CASE("Transaction IDs")
{
  const std::array valid_ids = {
    std::pair{std::string("1.1"), ccf::TxID{1, 1}},
    std::pair{std::string("42.100"), ccf::TxID{42, 100}},
    std::pair{
      std::to_string(std::numeric_limits<uint64_t>::max()) + "." +
        std::to_string(std::numeric_limits<uint64_t>::max()),
      ccf::TxID{
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<uint64_t>::max()}}};

  for (const auto& [input, expected] : valid_ids)
  {
    const auto parsed = ccf::TxID::from_str(input);
    REQUIRE(parsed.has_value());
    CHECK(parsed.value() == expected);
    CHECK(parsed->to_str() == input);
  }

  constexpr std::array invalid_ids = {
    "",
    "1",
    ".1",
    "0.1",
    "x.1",
    "1x.1",
    "1.",
    "1.0",
    "1.x",
    "1.1x",
    "1.1.1",
    "18446744073709551616.1",
    "1.18446744073709551616"};
  for (const auto input : invalid_ids)
  {
    CHECK_FALSE(ccf::TxID::from_str(input).has_value());
  }

  const ccf::TxID tx_id{2, 42};
  nlohmann::json json = tx_id;
  CHECK(json == "2.42");
  CHECK(json.get<ccf::TxID>() == tx_id);
  CHECK_THROWS_AS(nlohmann::json(42).get<ccf::TxID>(), ccf::JsonParseError);
  CHECK_THROWS_AS(nlohmann::json("0.42").get<ccf::TxID>(), ccf::JsonParseError);

  CHECK(
    ccf::schema_name(static_cast<const ccf::TxID*>(nullptr)) ==
    "TransactionId");
  nlohmann::json schema;
  ccf::fill_json_schema(schema, static_cast<const ccf::TxID*>(nullptr));
  CHECK(schema["type"] == "string");
  CHECK(schema["pattern"] == "^[0-9]+\\.[0-9]+$");
}

TEST_CASE("Proposal state formatting")
{
  constexpr std::array proposal_states = {
    std::pair{ccf::ProposalState::OPEN, "open"},
    std::pair{ccf::ProposalState::ACCEPTED, "accepted"},
    std::pair{ccf::ProposalState::WITHDRAWN, "withdrawn"},
    std::pair{ccf::ProposalState::REJECTED, "rejected"},
    std::pair{ccf::ProposalState::FAILED, "failed"},
    std::pair{ccf::ProposalState::DROPPED, "dropped"}};
  for (const auto& [state, expected] : proposal_states)
  {
    CHECK(fmt::format("{}", state) == expected);
  }
  CHECK_THROWS_AS(
    []() { return fmt::format("{}", static_cast<ccf::ProposalState>(255)); }(),
    std::logic_error);
}

TEST_CASE("PEM helpers")
{
  const std::string pem_a = "-----BEGIN A-----";
  const std::string pem_b = "-----BEGIN B-----";
  std::vector<uint8_t> bytes(pem_a.begin(), pem_a.end());

  const ccf::crypto::Pem from_vector(bytes);
  const ccf::crypto::Pem from_span{std::span<const uint8_t>(bytes)};
  const ccf::crypto::Pem from_string(pem_a);
  CHECK(from_vector == from_string);
  CHECK(from_span == from_string);
  CHECK(from_vector.raw() == bytes);
  CHECK(from_vector.size() == bytes.size());
  CHECK(
    std::string_view(
      reinterpret_cast<const char*>(from_vector.data()), from_vector.size()) ==
    pem_a);

  bytes.push_back('\0');
  ccf::crypto::Pem with_null_terminator(bytes);
  CHECK(with_null_terminator == from_string);
  CHECK(
    std::string_view(
      reinterpret_cast<const char*>(with_null_terminator.data()),
      with_null_terminator.size()) == pem_a);

  const ccf::crypto::Pem empty;
  const ccf::crypto::Pem later(pem_b);
  CHECK(empty.empty());
  CHECK_FALSE(from_string.empty());
  CHECK(from_string != later);
  CHECK(from_string < later);
  CHECK(
    std::hash<ccf::crypto::Pem>{}(from_string) ==
    std::hash<std::string>{}(pem_a));

  nlohmann::json json = from_string;
  CHECK(json == pem_a);
  CHECK(json.get<ccf::crypto::Pem>() == from_string);

  nlohmann::json array_json = nlohmann::json::array();
  for (const auto byte : from_string.raw())
  {
    array_json.push_back(byte);
  }
  CHECK(array_json.get<ccf::crypto::Pem>() == from_string);
  CHECK_THROWS_AS(
    nlohmann::json::object().get<ccf::crypto::Pem>(), std::runtime_error);

  CHECK(
    ccf::crypto::schema_name(static_cast<const ccf::crypto::Pem*>(nullptr)) ==
    "Pem");
  nlohmann::json schema;
  ccf::crypto::fill_json_schema(
    schema, static_cast<const ccf::crypto::Pem*>(nullptr));
  CHECK(schema == nlohmann::json{{"type", "string"}});
}

TEST_CASE("Transaction status strings")
{
  constexpr std::array statuses = {
    std::pair{ccf::TxStatus::Unknown, "Unknown"},
    std::pair{ccf::TxStatus::Pending, "Pending"},
    std::pair{ccf::TxStatus::Committed, "Committed"},
    std::pair{ccf::TxStatus::Invalid, "Invalid"}};
  for (const auto& [status, expected] : statuses)
  {
    CHECK(ccf::tx_status_to_str(status) == std::string_view(expected));
  }
  CHECK(
    ccf::tx_status_to_str(static_cast<ccf::TxStatus>(255)) ==
    std::string_view("Unhandled value"));
}

TEST_CASE("Subject alternative names")
{
  const ccf::crypto::SubjectAltName expected_ip{"127.0.0.1", true};
  const ccf::crypto::SubjectAltName expected_dns{"example.com", false};
  CHECK(ccf::crypto::san_from_string("iPAddress:127.0.0.1") == expected_ip);
  CHECK(ccf::crypto::san_from_string("dNSName:example.com") == expected_dns);
  CHECK(
    ccf::crypto::sans_from_string_list(
      {"iPAddress:127.0.0.1", "dNSName:example.com"}) ==
    std::vector{expected_ip, expected_dns});
  CHECK_THROWS_AS(
    ccf::crypto::san_from_string("email:test@example.com"), std::logic_error);

  CHECK(fmt::format("{}", expected_ip) == "IP:127.0.0.1");
  CHECK(fmt::format("{}", expected_dns) == "DNS:example.com");

  nlohmann::json json = expected_dns;
  CHECK(json.get<ccf::crypto::SubjectAltName>() == expected_dns);
}

TEST_CASE("Curve digest selection")
{
  using ccf::crypto::CurveID;
  using ccf::crypto::MDType;

  CHECK(ccf::crypto::get_md_for_ec(CurveID::SECP256R1) == MDType::SHA256);
  CHECK(ccf::crypto::get_md_for_ec(CurveID::SECP384R1) == MDType::SHA384);
  CHECK(ccf::crypto::get_md_for_ec(CurveID::SECP521R1) == MDType::SHA512);

  CHECK_THROWS_AS(ccf::crypto::get_md_for_ec(CurveID::NONE), std::logic_error);
  CHECK_THROWS_AS(
    ccf::crypto::get_md_for_ec(CurveID::CURVE25519), std::logic_error);
  CHECK_THROWS_AS(
    ccf::crypto::get_md_for_ec(CurveID::X25519), std::logic_error);
  CHECK_THROWS_AS(
    ccf::crypto::get_md_for_ec(static_cast<CurveID>(255)), std::logic_error);
}

TEST_CASE("Locking helpers")
{
  ccf::ds::Mutex mutex;
  CHECK(mutex.native_handle() != nullptr);

  ccf::ds::ConditionVariable condition_variable;
  std::atomic<bool> entered = false;
  std::atomic<bool> woke = false;
  std::thread waiter([&]() {
    ccf::ds::MutexGuard guard(mutex);
    entered.store(true, std::memory_order_release);
    condition_variable.wait(guard);
    woke.store(true, std::memory_order_release);
  });

  while (!entered.load(std::memory_order_acquire))
  {
    std::this_thread::yield();
  }

  {
    ccf::ds::MutexGuard guard(mutex);
    condition_variable.notify_one();
  }

  waiter.join();
  CHECK(woke.load(std::memory_order_acquire));
}

TEST_CASE("Claims digest schema")
{
  CHECK(
    ccf::schema_name(static_cast<const ccf::ClaimsDigest*>(nullptr)) ==
    "Sha256Digest");
  nlohmann::json schema;
  ccf::fill_json_schema(schema, static_cast<const ccf::ClaimsDigest*>(nullptr));
  CHECK(schema["type"] == "string");
  CHECK(schema["format"] == "hex");
  CHECK(schema["pattern"] == "^[a-f0-9]{32}$");
}

TEST_CASE("HTTP client error status")
{
  CHECK_FALSE(
    ccf::is_http_status_client_error(static_cast<ccf::http_status>(399)));
  CHECK(ccf::is_http_status_client_error(static_cast<ccf::http_status>(400)));
  CHECK(ccf::is_http_status_client_error(static_cast<ccf::http_status>(499)));
  CHECK_FALSE(
    ccf::is_http_status_client_error(static_cast<ccf::http_status>(500)));
}
