// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_NO_EXCEPTIONS_BUT_WITH_ALL_ASSERTS
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "kv/test/null_encryptor.h"
#include "node/client_signatures.h"
#include "node/genesis_gen.h"
#include "node/history.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/serdes.h"
#include "node/rpc/test/stub_consensus.h"
#include "node/rpc/user_frontend.h"
#include "node_stub.h"
#include "runtime_config/default_whitelists.h"
#include "tls/rsa_key_pair.h"

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
auto kp = tls::make_key_pair();
auto member_cert = kp -> self_sign("CN=name_member");
auto verifier_mem = tls::make_verifier(member_cert);
auto member_caller = verifier_mem -> der_cert_data();
auto user_cert = kp -> self_sign("CN=name_user");
auto dummy_enc_pubk = tls::make_rsa_key_pair() -> public_key_pem();

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
const auto gov_script_file = files::slurp_string(get_script_path("gov.lua"));

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

void set_whitelists(GenesisGenerator& gen)
{
  for (const auto& wl : default_whitelists)
    gen.set_whitelist(wl.first, wl.second);
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
  const tls::KeyPairPtr& kp_,
  const tls::Pem& caller,
  llhttp_method verb = HTTP_POST)
{
  http::Request r(fmt::format("/gov/{}", method_name), verb);

  const auto body = params.is_null() ? std::vector<uint8_t>() :
                                       serdes::pack(params, default_pack);
  r.set_body(&body);

  crypto::Sha256Hash hash;
  const auto contents = caller.contents();
  tls::do_hash(contents.data(), contents.size(), hash.h, MBEDTLS_MD_SHA256);
  const std::string key_id = fmt::format("{:02x}", fmt::join(hash.h, ""));

  http::sign_request(r, kp_, key_id);

  return r.build_request();
}

auto frontend_process(
  MemberRpcFrontend& frontend,
  const std::vector<uint8_t>& serialized_request,
  const tls::Pem& caller)
{
  auto session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, tls::make_verifier(caller)->der_cert_data());
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

auto get_cert(uint64_t member_id, tls::KeyPairPtr& kp_mem)
{
  return kp_mem->self_sign("CN=new member" + to_string(member_id));
}

DOCTEST_TEST_CASE("Proposer ballot")
{
  NetworkState network;
  network.tables->set_encryptor(encryptor);
  auto history = std::make_shared<ccf::NullTxHistory>(*network.tables, 0, *kp);
  network.tables->set_history(history);
  auto consensus = std::make_shared<aft::StubCFTConsensus>();
  network.tables->set_consensus(consensus);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});

  const auto proposer_cert = get_cert(0, kp);
  const auto proposer_id = gen.add_member(proposer_cert);
  gen.activate_member(proposer_id);
  const auto voter_cert = get_cert(1, kp);
  const auto voter_id = gen.add_member(voter_cert);
  gen.activate_member(voter_id);

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);

  frontend.open();
  const auto proposed_member = get_cert(2, kp);

  Propose::In proposal;
  proposal.script = std::string(R"xxx(
    tables, member_info = ...
    for i = 1,10000000,1
    do
    u = i ^ 0.5
    end
    return Calls:call("new_member", member_info)
  )xxx");
  proposal.parameter["cert"] = proposed_member;
  proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;
  const auto propose =
    create_signed_request(proposal, "proposals", kp, proposer_cert);

  Propose::Out out1;
  Propose::Out out2;

  auto fn = [](
              MemberRpcFrontend& f,
              const std::vector<uint8_t>& r,
              const tls::Pem& i,
              Propose::Out& o) {
    const auto rs = frontend_process(f, r, i);
    o = parse_response_body<Propose::Out>(rs);
  };

  auto t1 = std::thread(
    fn,
    std::ref(frontend),
    std::ref(propose),
    std::ref(proposer_cert),
    std::ref(out1));
  auto t2 = std::thread(
    fn,
    std::ref(frontend),
    std::ref(propose),
    std::ref(proposer_cert),
    std::ref(out2));
  t1.join();
  t2.join();

  DOCTEST_CHECK(out1.state == ProposalState::OPEN);
  DOCTEST_CHECK(out2.state == ProposalState::OPEN);
  DOCTEST_CHECK(out1.proposal_id != out2.proposal_id);

  auto metrics_req = create_request(nlohmann::json(), "api/metrics", HTTP_GET);
  auto metrics = frontend_process(frontend, metrics_req, proposer_cert);
  auto metrics_json = serdes::unpack(metrics.body, serdes::Pack::Text);
  for (auto& row : metrics_json["metrics"])
  {
    if (row["path"] == "proposals")
    {
      DOCTEST_CHECK(row["retries"] == 1);
    }
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
