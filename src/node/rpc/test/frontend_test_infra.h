// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_EXCEPTIONS_BUT_WITH_ALL_ASSERTS
#include "ccf/app_interface.h"
#include "ccf/user_frontend.h"
#include "crypto/rsa_key_pair.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/client_signatures.h"
#include "node/genesis_gen.h"
#include "node/history.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/serdes.h"
#include "node_stub.h"

#include <doctest/doctest.h>
#include <iostream>
#include <string>

using namespace ccfapp;
using namespace ccf;
using namespace std;
using namespace serdes;
using namespace nlohmann;

using TResponse = http::SimpleResponseProcessor::Response;

// used throughout
auto kp = crypto::make_key_pair();
auto member_cert = kp -> self_sign("CN=name_member");
auto verifier_mem = crypto::make_verifier(member_cert);
auto member_caller = verifier_mem -> cert_der();
auto user_cert = kp -> self_sign("CN=name_user");
auto dummy_enc_pubk = crypto::make_rsa_key_pair() -> public_key_pem();

auto encryptor = std::make_shared<kv::NullTxEncryptor>();

constexpr auto default_pack = serdes::Pack::Text;

string get_script_path(string name)
{
  auto default_dir = "../src/runtime_config";
  auto dir = getenv("RUNTIME_CONFIG_DIR");
  stringstream ss;
  ss << (dir ? dir : default_dir) << "/" << name;
  return ss.str();
}

template <typename T>
T parse_response_body(const TResponse& r)
{
  nlohmann::json body_j;
  try
  {
    body_j = serdes::unpack(r.body, serdes::Pack::Text);
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

void check_error(const TResponse& r, http_status expected)
{
  DOCTEST_CHECK(r.status == expected);
}

std::vector<uint8_t> create_request(
  const json& params, const string& method_name, llhttp_method verb = HTTP_POST)
{
  http::Request r(fmt::format("/gov/{}", method_name), verb);
  const auto body = params.is_null() ? std::vector<uint8_t>() :
                                       serdes::pack(params, default_pack);
  r.set_body(&body);
  return r.build_request();
}

std::vector<uint8_t> create_signed_request(
  const json& params,
  const string& method_name,
  const crypto::KeyPairPtr& kp_,
  const crypto::Pem& caller,
  llhttp_method verb = HTTP_POST)
{
  http::Request r(fmt::format("/gov/{}", method_name), verb);

  const auto body = params.is_null() ? std::vector<uint8_t>() :
                                       serdes::pack(params, default_pack);
  r.set_body(&body);

  const auto contents = caller.contents();
  auto caller_der = crypto::cert_pem_to_der(caller);
  const auto key_id = crypto::Sha256Hash(caller_der).hex_str();

  http::sign_request(r, kp_, key_id);

  return r.build_request();
}

auto frontend_process(
  MemberRpcFrontend& frontend,
  const std::vector<uint8_t>& serialized_request,
  const crypto::Pem& caller)
{
  auto session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, crypto::make_verifier(caller)->cert_der());
  auto rpc_ctx = enclave::make_rpc_context(session, serialized_request);
  http::extract_actor(*rpc_ctx);
  auto serialized_response = frontend.process(rpc_ctx);

  DOCTEST_CHECK(serialized_response.has_value());

  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  parser.execute(serialized_response->data(), serialized_response->size());
  DOCTEST_REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

auto get_vote(
  MemberRpcFrontend& frontend,
  ProposalId proposal_id,
  const MemberId& voter,
  const crypto::Pem& caller)
{
  const auto getter = create_request(
    nullptr,
    fmt::format("proposals/{}/ballots/{}", proposal_id, voter),
    HTTP_GET);

  return parse_response_body<Script>(
    frontend_process(frontend, getter, caller));
}

auto activate(
  MemberRpcFrontend& frontend,
  const crypto::KeyPairPtr& kp,
  const crypto::Pem& caller)
{
  const auto state_digest_req =
    create_request(nullptr, "ack/update_state_digest");
  const auto ack = parse_response_body<StateDigest>(
    frontend_process(frontend, state_digest_req, caller));

  StateDigest params;
  params.state_digest = ack.state_digest;
  const auto ack_req = create_signed_request(params, "ack", kp, caller);
  return frontend_process(frontend, ack_req, caller);
}

auto get_cert(uint64_t member_id, crypto::KeyPairPtr& kp_mem)
{
  return kp_mem->self_sign("CN=new member" + to_string(member_id));
}

auto init_frontend(
  NetworkState& network,
  GenesisGenerator& gen,
  StubNodeContext& context,
  ShareManager& share_manager,
  const int n_members,
  std::vector<crypto::Pem>& member_certs)
{
  // create members
  for (uint8_t i = 0; i < n_members; i++)
  {
    member_certs.push_back(get_cert(i, kp));
    gen.activate_member(gen.add_member(member_certs.back()));
  }

  return MemberRpcFrontend(network, context, share_manager);
}

void init_network(NetworkState& network)
{
  network.tables->set_encryptor(encryptor);
  auto history = std::make_shared<ccf::NullTxHistory>(
    *network.tables, kv::test::PrimaryNodeId, *kp);
  network.tables->set_history(history);
  auto consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network.tables->set_consensus(consensus);
}