// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_EXCEPTIONS_BUT_WITH_ALL_ASSERTS
#include "ccf/app_interface.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/service/signed_req.h"
#include "ds/files.h"
#include "ds/internal_logger.h.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/user_frontend.h"
#include "node_stub.h"

#include <doctest/doctest.h>
#include <iostream>
#include <string>

using namespace ccf;
using namespace ccf;
using namespace std;
using namespace nlohmann;

using TResponse = ::http::SimpleResponseProcessor::Response;

// used throughout
constexpr size_t certificate_validity_period_days = 365;
using namespace std::literals;
auto valid_from =
  ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
auto valid_to = ccf::crypto::compute_cert_valid_to_string(
  valid_from, certificate_validity_period_days);

auto kp = ccf::crypto::make_key_pair();
auto member_cert = kp->self_sign("CN=name_member", valid_from, valid_to);
auto verifier_mem = ccf::crypto::make_verifier(member_cert);
auto user_cert = kp->self_sign("CN=name_user", valid_from, valid_to);
auto dummy_enc_pubk = ccf::crypto::make_rsa_key_pair()->public_key_pem();

auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

template <typename T>
T parse_response_body(const TResponse& r)
{
  nlohmann::json body_j;
  try
  {
    body_j = nlohmann::json::parse(r.body);
  }
  catch (const nlohmann::json::parse_error& e)
  {
    LOG_FAIL_FMT("RPC error: {}", e.what());
    LOG_FAIL_FMT("RPC error: {}", std::string(r.body.begin(), r.body.end()));
  }

  return body_j.get<T>();
}

std::string parse_response_body(const TResponse& r)
{
  return std::string(r.body.begin(), r.body.end());
}

void check_error(const TResponse& r, ccf::http_status expected)
{
  DOCTEST_CHECK(r.status == expected);
}

void check_error_message(const TResponse& r, const std::string& msg)
{
  const std::string body_s(r.body.begin(), r.body.end());
  CHECK(body_s.find(msg) != std::string::npos);
}

std::vector<uint8_t> create_request(
  const json& params, const string& method_name, llhttp_method verb = HTTP_POST)
{
  ::http::Request r(fmt::format("/gov/{}", method_name), verb);
  const auto body = params.is_null() ? std::string() : params.dump();
  r.set_body(body);
  return r.build_request();
}

auto frontend_process(
  MemberRpcFrontend& frontend,
  const std::vector<uint8_t>& serialized_request,
  const ccf::crypto::Pem& caller)
{
  auto session = std::make_shared<ccf::SessionContext>(
    ccf::InvalidSessionId, ccf::crypto::make_verifier(caller)->cert_der());
  auto rpc_ctx = ccf::make_rpc_context(session, serialized_request);
  ::http::extract_actor(*rpc_ctx);
  frontend.process(rpc_ctx);
  DOCTEST_CHECK(!rpc_ctx->response_is_pending);

  auto serialized_response = rpc_ctx->serialise_response();

  ::http::SimpleResponseProcessor processor;
  ::http::ResponseParser parser(processor);

  parser.execute(serialized_response.data(), serialized_response.size());
  DOCTEST_REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

auto get_cert(uint64_t member_id, ccf::crypto::KeyPairPtr& kp_mem)
{
  return kp_mem->self_sign(
    "CN=new member" + to_string(member_id), valid_from, valid_to);
}

std::unique_ptr<ccf::NetworkIdentity> make_test_network_ident()
{
  using namespace std::literals;
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
  return std::make_unique<ccf::NetworkIdentity>(
    "CN=CCF test network",
    ccf::crypto::service_identity_curve_choice,
    valid_from,
    2);
}

void init_network(NetworkState& network)
{
  network.tables->set_encryptor(encryptor);
  auto history = std::make_shared<ccf::NullTxHistory>(
    *network.tables, ccf::kv::test::PrimaryNodeId, *kp);
  network.tables->set_history(history);
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  network.tables->set_consensus(consensus);
  network.identity = make_test_network_ident();
}