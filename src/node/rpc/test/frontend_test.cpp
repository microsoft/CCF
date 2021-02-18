// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#include "consensus/aft/request.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "kv/map.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/entities.h"
#include "node/genesis_gen.h"
#include "node/history.h"
#include "node/network_state.h"
#include "node/rpc/json_handler.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/serdes.h"
#include "node/rpc/user_frontend.h"
#include "node/test/channel_stub.h"
#include "node_stub.h"

#include <doctest/doctest.h>
#include <iostream>
#include <string>

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

using namespace ccfapp;
using namespace ccf;
using namespace std;

static constexpr auto default_pack = serdes::Pack::MsgPack;

class BaseTestFrontend : public SimpleUserRpcFrontend
{
public:
  ccf::StubNodeState stub_node;

  BaseTestFrontend(kv::Store& tables) : SimpleUserRpcFrontend(tables, stub_node)
  {}

  // For testing only, we don't need to specify auth policies everywhere and
  // default to no auth
  ccf::EndpointRegistry::Endpoint make_endpoint(
    const std::string& method,
    RESTVerb verb,
    const EndpointFunction& f,
    const ccf::endpoints::AuthnPolicies& ap = no_auth_required)
  {
    return endpoints.make_endpoint(method, verb, f, ap);
  }
};

class TestUserFrontend : public BaseTestFrontend
{
public:
  TestUserFrontend(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto empty_function = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint(
      "empty_function", HTTP_POST, empty_function, {user_cert_auth_policy})
      .set_forwarding_required(ForwardingRequired::Sometimes)
      .install();

    auto empty_function_signed = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint(
      "empty_function_signed",
      HTTP_POST,
      empty_function_signed,
      {user_signature_auth_policy})
      .set_forwarding_required(ForwardingRequired::Sometimes)
      .install();

    auto empty_function_no_auth = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint(
      "empty_function_no_auth",
      HTTP_POST,
      empty_function_no_auth,
      no_auth_required)
      .set_forwarding_required(ForwardingRequired::Sometimes)
      .install();
  }
};

class TestMinimalEndpointFunction : public BaseTestFrontend
{
public:
  TestMinimalEndpointFunction(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto echo_function = [this](kv::Tx& tx, nlohmann::json&& params) {
      return make_success(std::move(params));
    };
    make_endpoint("echo", HTTP_POST, json_adapter(echo_function)).install();

    auto get_caller_function = [this](EndpointContext& ctx, nlohmann::json&&) {
      const auto& ident = ctx.get_caller<UserCertAuthnIdentity>();
      return make_success(ident.user_id);
    };
    make_endpoint(
      "get_caller",
      HTTP_POST,
      json_adapter(get_caller_function),
      {user_cert_auth_policy})
      .install();

    auto failable_function = [this](kv::Tx& tx, nlohmann::json&& params) {
      const auto it = params.find("error");
      if (it != params.end())
      {
        const http_status error_code = (*it)["code"];
        const std::string error_msg = (*it)["message"];

        return make_error((http_status)error_code, "Error", error_msg);
      }

      return make_success(true);
    };
    make_endpoint("failable", HTTP_POST, json_adapter(failable_function))
      .install();
  }
};

class TestRestrictedVerbsFrontend : public BaseTestFrontend
{
public:
  TestRestrictedVerbsFrontend(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto get_only = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("get_only", HTTP_GET, get_only).install();

    auto post_only = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("post_only", HTTP_POST, post_only).install();

    auto put_or_delete = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("put_or_delete", HTTP_PUT, put_or_delete).install();
    make_endpoint("put_or_delete", HTTP_DELETE, put_or_delete).install();
  }
};

class TestExplicitCommitability : public BaseTestFrontend
{
public:
  kv::Map<size_t, size_t> values;

  TestExplicitCommitability(kv::Store& tables) :
    BaseTestFrontend(tables),
    values("test_values")
  {
    open();

    auto maybe_commit = [this](EndpointContext& args) {
      const auto parsed =
        serdes::unpack(args.rpc_ctx->get_request_body(), default_pack);

      const auto new_value = parsed["value"].get<size_t>();
      auto vs = args.tx.rw(values);
      vs->put(0, new_value);

      const auto apply_it = parsed.find("apply");
      if (apply_it != parsed.end())
      {
        const auto should_apply = apply_it->get<bool>();
        args.rpc_ctx->set_apply_writes(should_apply);
      }

      const auto status = parsed["status"].get<http_status>();
      args.rpc_ctx->set_response_status(status);
    };
    make_endpoint("maybe_commit", HTTP_POST, maybe_commit).install();
  }
};

class TestAlternativeHandlerTypes : public BaseTestFrontend
{
public:
  TestAlternativeHandlerTypes(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto command = [this](CommandEndpointContext& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_command_endpoint("command", HTTP_POST, command, no_auth_required)
      .install();

    auto read_only = [this](ReadOnlyEndpointContext& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_read_only_endpoint("read_only", HTTP_POST, read_only, no_auth_required)
      .install();
    make_read_only_endpoint("read_only", HTTP_GET, read_only, no_auth_required)
      .install();
  }
};

class TestTemplatedPaths : public BaseTestFrontend
{
public:
  TestTemplatedPaths(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto endpoint = [this](auto& args) {
      nlohmann::json response_body = args.rpc_ctx->get_request_path_params();
      args.rpc_ctx->set_response_body(response_body.dump(2));
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("{foo}/{bar}/{baz}", HTTP_POST, endpoint).install();
  }
};

class TestMemberFrontend : public MemberRpcFrontend
{
public:
  TestMemberFrontend(
    ccf::NetworkState& network,
    ccf::StubNodeState& node,
    ccf::ShareManager& share_manager) :
    MemberRpcFrontend(network, node, share_manager)
  {
    open();

    auto empty_function = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    member_endpoints
      .make_endpoint(
        "empty_function", HTTP_POST, empty_function, {member_cert_auth_policy})
      .set_forwarding_required(ForwardingRequired::Sometimes)
      .install();
  }
};

class TestNoCertsFrontend : public RpcFrontend
{
  EndpointRegistry endpoints;

public:
  TestNoCertsFrontend(kv::Store& tables) :
    RpcFrontend(tables, endpoints),
    endpoints("test")
  {
    open();

    auto empty_function = [this](auto& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    endpoints
      .make_endpoint(
        "empty_function", HTTP_POST, empty_function, no_auth_required)
      .set_forwarding_required(ForwardingRequired::Sometimes)
      .install();
  }
};

//
// User, Node and Member frontends used for forwarding tests
//

class RpcContextRecorder
{
public:
  // session->caller_cert may be DER or PEM, we always convert to PEM
  tls::Pem last_caller_cert;
  CallerId last_caller_id = INVALID_ID;

  void record_ctx(EndpointContext& ctx)
  {
    last_caller_cert = tls::cert_der_to_pem(ctx.rpc_ctx->session->caller_cert);
    if (const auto uci = ctx.try_get_caller<UserCertAuthnIdentity>())
    {
      last_caller_id = uci->user_id;
    }
    else if (const auto mci = ctx.try_get_caller<MemberCertAuthnIdentity>())
    {
      last_caller_id = mci->member_id;
    }
    else
    {
      last_caller_id = INVALID_ID;
    }
  }
};

class TestForwardingUserFrontEnd : public BaseTestFrontend,
                                   public RpcContextRecorder
{
public:
  TestForwardingUserFrontEnd(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto empty_function = [this](auto& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    make_endpoint(
      "empty_function", HTTP_POST, empty_function, {user_cert_auth_policy})
      .install();

    auto empty_function_no_auth = [this](auto& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("empty_function_no_auth", HTTP_POST, empty_function_no_auth)
      .install();
  }
};

class TestForwardingNodeFrontEnd : public NodeRpcFrontend,
                                   public RpcContextRecorder
{
public:
  TestForwardingNodeFrontEnd(
    ccf::NetworkState& network, ccf::StubNodeState& node) :
    NodeRpcFrontend(network, node)
  {
    open();

    auto empty_function = [this](auto& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    endpoints
      .make_endpoint(
        "empty_function", HTTP_POST, empty_function, no_auth_required)
      .install();
  }
};

class TestForwardingMemberFrontEnd : public MemberRpcFrontend,
                                     public RpcContextRecorder
{
public:
  TestForwardingMemberFrontEnd(
    kv::Store& tables,
    ccf::NetworkState& network,
    ccf::StubNodeState& node,
    ccf::ShareManager& share_manager) :
    MemberRpcFrontend(network, node, share_manager)
  {
    open();

    auto empty_function = [this](auto& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    endpoints
      .make_endpoint(
        "empty_function", HTTP_POST, empty_function, {member_cert_auth_policy})
      .install();
  }
};

// used throughout
auto kp = tls::make_key_pair();
auto encryptor = std::make_shared<kv::NullTxEncryptor>();

NetworkState bft_network(ConsensusType::BFT);
auto history_kp = tls::make_key_pair();

auto history =
  std::make_shared<NullTxHistory>(*bft_network.tables, 0, *history_kp);

auto create_simple_request(
  const std::string& method = "empty_function",
  serdes::Pack pack = default_pack)
{
  http::Request request(method);
  request.set_header(
    http::headers::CONTENT_TYPE, ccf::jsonhandler::pack_to_content_type(pack));
  return request;
}

http::Request create_signed_request(
  const tls::Pem& caller_cert,
  const http::Request& r = create_simple_request(),
  const std::vector<uint8_t>* body = nullptr)
{
  http::Request s(r);

  s.set_body(body);

  const auto contents = caller_cert.contents();
  crypto::Sha256Hash hash({contents.data(), contents.size()});
  const std::string key_id = fmt::format("{:02x}", fmt::join(hash.h, ""));

  http::sign_request(s, kp, key_id);

  return s;
}

http::SimpleResponseProcessor::Response parse_response(const vector<uint8_t>& v)
{
  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  parser.execute(v.data(), v.size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

nlohmann::json parse_response_body(
  const vector<uint8_t>& body, serdes::Pack pack = default_pack)
{
  return serdes::unpack(body, pack);
}

// callers used throughout
auto user_caller = kp -> self_sign("CN=name");
auto user_caller_der = tls::make_verifier(user_caller) -> cert_der();

auto member_caller = kp -> self_sign("CN=name_member");
auto member_caller_der = tls::make_verifier(member_caller) -> cert_der();

auto node_caller = kp -> self_sign("CN=node");
auto node_caller_der = tls::make_verifier(node_caller) -> cert_der();

auto kp_other = tls::make_key_pair();
auto invalid_caller = kp_other -> self_sign("CN=name");
auto invalid_caller_der = tls::make_verifier(invalid_caller) -> cert_der();

auto anonymous_caller_der = std::vector<uint8_t>();

auto user_session = make_shared<enclave::SessionContext>(
  enclave::InvalidSessionId, user_caller_der);
auto backup_user_session = make_shared<enclave::SessionContext>(
  enclave::InvalidSessionId, user_caller_der);
auto invalid_session = make_shared<enclave::SessionContext>(
  enclave::InvalidSessionId, invalid_caller_der);
auto member_session = make_shared<enclave::SessionContext>(
  enclave::InvalidSessionId, member_caller_der);
auto anonymous_session = make_shared<enclave::SessionContext>(
  enclave::InvalidSessionId, anonymous_caller_der);

UserId user_id = INVALID_ID;
UserId invalid_user_id = INVALID_ID;

MemberId member_id = INVALID_ID;
MemberId invalid_member_id = INVALID_ID;

void prepare_callers(NetworkState& network)
{
  // It is necessary to set a consensus before committing the first transaction,
  // so that the KV batching done before calling into replicate() stays in
  // order.
  auto backup_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto tx = network.tables->create_tx();
  network.tables->set_encryptor(encryptor);

  GenesisGenerator g(network, tx);
  g.init_values();
  g.create_service({});
  user_id = g.add_user({user_caller});
  member_id = g.add_member(member_caller);
  invalid_member_id = g.add_member(invalid_caller);
  CHECK(g.finalize() == kv::CommitResult::SUCCESS);
}

void add_callers_bft_store()
{
  auto gen_tx = bft_network.tables->create_tx();
  bft_network.tables->set_encryptor(encryptor);
  bft_network.tables->set_history(history);
  auto backup_consensus =
    std::make_shared<kv::PrimaryStubConsensus>(ConsensusType::BFT);
  bft_network.tables->set_consensus(backup_consensus);

  GenesisGenerator g(bft_network, gen_tx);
  g.init_values();
  g.create_service({});
  user_id = g.add_user({user_caller});
  CHECK(g.finalize() == kv::CommitResult::SUCCESS);
}

TEST_CASE("process_bft")
{
  add_callers_bft_store();
  TestUserFrontend frontend(*bft_network.tables);
  auto simple_call = create_simple_request();

  const nlohmann::json call_body = {{"foo", "bar"}, {"baz", 42}};
  const auto serialized_body = serdes::pack(call_body, default_pack);
  simple_call.set_body(&serialized_body);

  kv::TxHistory::RequestID rid = {1, 1};

  const auto serialized_call = simple_call.build_request();
  aft::Request request = {
    rid, user_caller_der, serialized_call, enclave::FrameFormat::http};

  auto session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, user_caller_der);
  auto ctx = enclave::make_rpc_context(session, request.raw);
  ctx->execute_on_node = true;
  frontend.process_bft(ctx);

  auto tx = bft_network.tables->create_tx();
  auto aft_requests = tx.rw<aft::RequestsMap>(ccf::Tables::AFT_REQUESTS);
  auto request_value = aft_requests->get(0);
  REQUIRE(request_value.has_value());

  aft::Request deserialised_req = request_value.value();

  REQUIRE(deserialised_req.caller_cert == user_caller_der);
  REQUIRE(deserialised_req.raw == serialized_call);
  REQUIRE(deserialised_req.frame_format == enclave::FrameFormat::http);
}

TEST_CASE("SignedReq to and from json")
{
  SignedReq sr;
  REQUIRE(sr.sig.empty());
  REQUIRE(sr.req.empty());

  nlohmann::json j = sr;

  sr = j;
  REQUIRE(sr.sig.empty());
  REQUIRE(sr.req.empty());
}

TEST_CASE("process with signatures")
{
  NetworkState network;
  prepare_callers(network);
  TestUserFrontend frontend(*network.tables);

  SUBCASE("missing rpc")
  {
    constexpr auto rpc_name = "this_rpc_doesnt_exist";
    const auto invalid_call = create_simple_request(rpc_name);
    const auto serialized_call = invalid_call.build_request();
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    REQUIRE(response.status == HTTP_STATUS_NOT_FOUND);
  }

  SUBCASE("endpoint does not require signature")
  {
    const auto simple_call = create_simple_request();
    const auto signed_call = create_signed_request(user_caller, simple_call);
    const auto serialized_simple_call = simple_call.build_request();
    const auto serialized_signed_call = signed_call.build_request();

    auto simple_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_simple_call);
    auto signed_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_signed_call);

    INFO("Unsigned RPC");
    {
      const auto serialized_response = frontend.process(simple_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Signed RPC");
    {
      const auto serialized_response = frontend.process(signed_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }
  }

  SUBCASE("endpoint requires signature")
  {
    const auto simple_call = create_simple_request("empty_function_signed");
    const auto signed_call = create_signed_request(user_caller, simple_call);
    const auto serialized_simple_call = simple_call.build_request();
    const auto serialized_signed_call = signed_call.build_request();

    auto simple_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_simple_call);
    auto signed_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_signed_call);

    INFO("Unsigned RPC");
    {
      const auto serialized_response = frontend.process(simple_rpc_ctx).value();
      auto response = parse_response(serialized_response);

      CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(error_msg.find("Missing signature") != std::string::npos);
    }

    INFO("Signed RPC");
    {
      const auto serialized_response = frontend.process(signed_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }
  }
}

TEST_CASE("process with caller")
{
  NetworkState network;
  prepare_callers(network);
  TestUserFrontend frontend(*network.tables);

  SUBCASE("endpoint does not require valid caller")
  {
    const auto simple_call = create_simple_request("empty_function_no_auth");
    const auto serialized_simple_call = simple_call.build_request();
    auto authenticated_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_simple_call);
    auto invalid_rpc_ctx =
      enclave::make_rpc_context(invalid_session, serialized_simple_call);
    auto anonymous_rpc_ctx =
      enclave::make_rpc_context(anonymous_session, serialized_simple_call);

    INFO("Valid authentication");
    {
      const auto serialized_response =
        frontend.process(authenticated_rpc_ctx).value();
      auto response = parse_response(serialized_response);

      // Even though the RPC does not require authenticated caller, an
      // authenticated RPC succeeds
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Invalid authentication");
    {
      const auto serialized_response =
        frontend.process(invalid_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Anonymous caller");
    {
      const auto serialized_response =
        frontend.process(anonymous_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }
  }

  SUBCASE("endpoint requires valid caller")
  {
    const auto simple_call = create_simple_request("empty_function");
    const auto serialized_simple_call = simple_call.build_request();
    auto authenticated_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_simple_call);
    auto invalid_rpc_ctx =
      enclave::make_rpc_context(invalid_session, serialized_simple_call);
    auto anonymous_rpc_ctx =
      enclave::make_rpc_context(anonymous_session, serialized_simple_call);

    INFO("Valid authentication");
    {
      const auto serialized_response =
        frontend.process(authenticated_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Invalid authentication");
    {
      const auto serialized_response =
        frontend.process(invalid_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_UNAUTHORIZED);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(
        error_msg.find("Could not find matching user certificate") !=
        std::string::npos);
    }

    INFO("Anonymous caller");
    {
      const auto serialized_response =
        frontend.process(anonymous_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_UNAUTHORIZED);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(
        error_msg.find("Could not find matching user certificate") !=
        std::string::npos);
    }
  }
}

TEST_CASE("No certs table")
{
  NetworkState network;
  prepare_callers(network);
  TestNoCertsFrontend frontend(*network.tables);
  auto simple_call = create_simple_request();
  std::vector<uint8_t> serialized_call = simple_call.build_request();

  INFO("Authenticated caller");
  {
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_OK);
  }

  INFO("Anonymous caller");
  {
    auto rpc_ctx =
      enclave::make_rpc_context(anonymous_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_OK);
  }
}

TEST_CASE("Member caller")
{
  NetworkState network;
  prepare_callers(network);

  ShareManager share_manager(network);
  StubNodeState stub_node;

  auto simple_call = create_simple_request();
  std::vector<uint8_t> serialized_call = simple_call.build_request();
  TestMemberFrontend frontend(network, stub_node, share_manager);

  SUBCASE("valid caller")
  {
    auto member_rpc_ctx =
      enclave::make_rpc_context(member_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(member_rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_OK);
  }

  SUBCASE("invalid caller")
  {
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
  }
}

TEST_CASE("MinimalEndpointFunction")
{
  NetworkState network;
  prepare_callers(network);
  TestMinimalEndpointFunction frontend(*network.tables);
  for (const auto pack_type : {serdes::Pack::Text, serdes::Pack::MsgPack})
  {
    {
      INFO("Calling echo, with params in body");
      auto echo_call = create_simple_request("echo", pack_type);
      const nlohmann::json j_body = {{"data", {"nested", "Some string"}},
                                     {"other", "Another string"}};
      const auto serialized_body = serdes::pack(j_body, pack_type);
      echo_call.set_body(serialized_body.data(), serialized_body.size());
      const auto serialized_call = echo_call.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response = parse_response(frontend.process(rpc_ctx).value());
      CHECK(response.status == HTTP_STATUS_OK);

      const auto response_body = parse_response_body(response.body, pack_type);
      CHECK(response_body == j_body);
    }

    {
      INFO("Calling echo, with params in query");
      auto echo_call = create_simple_request("echo", pack_type);
      const nlohmann::json j_params = {{"foo", "helloworld"},
                                       {"bar", 1},
                                       {"fooz", "2"},
                                       {"baz", "\"awkward\"\"escapes"}};
      echo_call.set_query_params(j_params);
      const auto serialized_call = echo_call.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response = parse_response(frontend.process(rpc_ctx).value());
      CHECK(response.status == HTTP_STATUS_OK);

      const auto response_body = parse_response_body(response.body, pack_type);
      CHECK(response_body == j_params);
    }

    {
      INFO("Calling get_caller");
      const auto get_caller = create_simple_request("get_caller", pack_type);
      const auto serialized_call = get_caller.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response = parse_response(frontend.process(rpc_ctx).value());
      CHECK(response.status == HTTP_STATUS_OK);

      const auto response_body = parse_response_body(response.body, pack_type);
      CHECK(response_body == user_id);
    }
  }

  {
    INFO("Calling failable, without failing");
    auto dont_fail = create_simple_request("failable");
    const auto serialized_call = dont_fail.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
    auto response = parse_response(frontend.process(rpc_ctx).value());
    CHECK(response.status == HTTP_STATUS_OK);
  }

  {
    for (const auto err : {
           HTTP_STATUS_INTERNAL_SERVER_ERROR,
           HTTP_STATUS_BAD_REQUEST,
           (http_status)418 // Teapot
         })
    {
      INFO("Calling failable, with error");
      const auto msg = fmt::format("An error message about {}", err);
      auto fail = create_simple_request("failable");
      const nlohmann::json j_body = {
        {"error", {{"code", err}, {"message", msg}}}};
      const auto serialized_body = serdes::pack(j_body, default_pack);
      fail.set_body(serialized_body.data(), serialized_body.size());
      const auto serialized_call = fail.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response = parse_response(frontend.process(rpc_ctx).value());
      CHECK(response.status == err);
      CHECK(
        response.headers[http::headers::CONTENT_TYPE] ==
        http::headervalues::contenttype::JSON);
      const std::string body_s(response.body.begin(), response.body.end());
      auto body_j = nlohmann::json::parse(body_s);
      CHECK(body_j["error"]["message"] == msg);
    }
  }
}

TEST_CASE("Restricted verbs")
{
  NetworkState network;
  prepare_callers(network);
  TestRestrictedVerbsFrontend frontend(*network.tables);

  for (auto verb = HTTP_DELETE; verb <= HTTP_SOURCE;
       verb = (llhttp_method)(size_t(verb) + 1))
  {
    INFO(llhttp_method_name(verb));

    {
      http::Request get("get_only", verb);
      const auto serialized_get = get.build_request();
      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_get);
      const auto serialized_response = frontend.process(rpc_ctx).value();
      const auto response = parse_response(serialized_response);
      if (verb == HTTP_GET)
      {
        CHECK(response.status == HTTP_STATUS_OK);
      }
      else
      {
        CHECK(response.status == HTTP_STATUS_METHOD_NOT_ALLOWED);
        const auto it = response.headers.find(http::headers::ALLOW);
        REQUIRE(it != response.headers.end());
        const auto v = it->second;
        CHECK(v.find(llhttp_method_name(HTTP_GET)) != std::string::npos);
      }
    }

    {
      http::Request post("post_only", verb);
      const auto serialized_post = post.build_request();
      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_post);
      const auto serialized_response = frontend.process(rpc_ctx).value();
      const auto response = parse_response(serialized_response);
      if (verb == HTTP_POST)
      {
        CHECK(response.status == HTTP_STATUS_OK);
      }
      else
      {
        CHECK(response.status == HTTP_STATUS_METHOD_NOT_ALLOWED);
        const auto it = response.headers.find(http::headers::ALLOW);
        REQUIRE(it != response.headers.end());
        const auto v = it->second;
        CHECK(v.find(llhttp_method_name(HTTP_POST)) != std::string::npos);
      }
    }

    {
      http::Request put_or_delete("put_or_delete", verb);
      const auto serialized_put_or_delete = put_or_delete.build_request();
      auto rpc_ctx =
        enclave::make_rpc_context(user_session, serialized_put_or_delete);
      const auto serialized_response = frontend.process(rpc_ctx).value();
      const auto response = parse_response(serialized_response);
      if (verb == HTTP_PUT || verb == HTTP_DELETE)
      {
        CHECK(response.status == HTTP_STATUS_OK);
      }
      else
      {
        CHECK(response.status == HTTP_STATUS_METHOD_NOT_ALLOWED);
        const auto it = response.headers.find(http::headers::ALLOW);
        REQUIRE(it != response.headers.end());
        const auto v = it->second;
        CHECK(v.find(llhttp_method_name(HTTP_PUT)) != std::string::npos);
        CHECK(v.find(llhttp_method_name(HTTP_DELETE)) != std::string::npos);
        CHECK(v.find(llhttp_method_name(verb)) == std::string::npos);
      }
    }
  }
}

TEST_CASE("Explicit commitability")
{
  NetworkState network;
  prepare_callers(network);
  TestExplicitCommitability frontend(*network.tables);

#define XX(num, name, string) HTTP_STATUS_##name,
  std::vector<http_status> all_statuses = {HTTP_STATUS_MAP(XX)};
#undef XX

  size_t next_value = 0;

  auto get_value = [&]() {
    auto tx = network.tables->create_tx();
    auto values = tx.rw(frontend.values);
    auto actual_v = values->get(0).value();
    return actual_v;
  };

  // Set initial value
  {
    auto tx = network.tables->create_tx();
    tx.rw(frontend.values)->put(0, next_value);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  for (const auto status : all_statuses)
  {
    INFO(http_status_str(status));

    {
      INFO("Without override...");
      const auto new_value = ++next_value;

      http::Request request("maybe_commit", HTTP_POST);

      const nlohmann::json request_body = {{"value", new_value},
                                           {"status", status}};
      const auto serialized_body = serdes::pack(request_body, default_pack);
      request.set_body(&serialized_body);

      const auto serialized_request = request.build_request();
      auto rpc_ctx =
        enclave::make_rpc_context(user_session, serialized_request);
      const auto serialized_response = frontend.process(rpc_ctx).value();
      const auto response = parse_response(serialized_response);

      CHECK(response.status == status);

      const auto applied_value = get_value();

      if (status >= 200 && status < 300)
      {
        INFO("...2xx statuses are applied");
        CHECK(applied_value == new_value);
      }
      else
      {
        INFO("...error statuses are reverted");
        CHECK(applied_value != new_value);
      }
    }

    {
      INFO("With override...");

      for (bool apply : {false, true})
      {
        const auto new_value = ++next_value;

        http::Request request("maybe_commit", HTTP_POST);

        const nlohmann::json request_body = {
          {"value", new_value}, {"apply", apply}, {"status", status}};
        const auto serialized_body = serdes::pack(request_body, default_pack);
        request.set_body(&serialized_body);

        const auto serialized_request = request.build_request();
        auto rpc_ctx =
          enclave::make_rpc_context(user_session, serialized_request);
        const auto serialized_response = frontend.process(rpc_ctx).value();
        const auto response = parse_response(serialized_response);

        CHECK(response.status == status);

        const auto applied_value = get_value();

        if (apply)
        {
          INFO("...a request can be applied regardless of status");
          CHECK(applied_value == new_value);
        }
        else
        {
          INFO("...a request can be reverted regardless of status");
          CHECK(applied_value != new_value);
        }
      }
    }
  }
}

TEST_CASE("Alternative endpoints")
{
  NetworkState network;
  prepare_callers(network);
  TestAlternativeHandlerTypes frontend(*network.tables);

  {
    auto command = create_simple_request("command");
    const auto serialized_command = command.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_command);
    auto response = parse_response(frontend.process(rpc_ctx).value());
    CHECK(response.status == HTTP_STATUS_OK);
  }

  for (auto verb : {HTTP_GET, HTTP_POST})
  {
    http::Request read_only("read_only", verb);
    const auto serialized_read_only = read_only.build_request();

    auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_read_only);
    auto response = parse_response(frontend.process(rpc_ctx).value());
    CHECK(response.status == HTTP_STATUS_OK);
  }
}

TEST_CASE("Templated paths")
{
  NetworkState network;
  prepare_callers(network);
  TestTemplatedPaths frontend(*network.tables);

  {
    auto request = create_simple_request("fin/fang/foom");
    const auto serialized_request = request.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_request);
    auto response = parse_response(frontend.process(rpc_ctx).value());
    CHECK(response.status == HTTP_STATUS_OK);

    std::map<std::string, std::string> expected_mapping;
    expected_mapping["foo"] = "fin";
    expected_mapping["bar"] = "fang";
    expected_mapping["baz"] = "foom";

    const auto response_json = nlohmann::json::parse(response.body);
    const auto actual_mapping = response_json.get<decltype(expected_mapping)>();

    CHECK(expected_mapping == actual_mapping);
  }

  {
    auto request = create_simple_request("users/1/address");
    const auto serialized_request = request.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_request);
    auto response = parse_response(frontend.process(rpc_ctx).value());
    CHECK(response.status == HTTP_STATUS_OK);

    std::map<std::string, std::string> expected_mapping;
    expected_mapping["foo"] = "users";
    expected_mapping["bar"] = "1";
    expected_mapping["baz"] = "address";

    const auto response_json = nlohmann::json::parse(response.body);
    const auto actual_mapping = response_json.get<decltype(expected_mapping)>();

    CHECK(expected_mapping == actual_mapping);
  }
}

TEST_CASE("Signed read requests can be executed on backup")
{
  NetworkState network;
  prepare_callers(network);
  TestUserFrontend frontend(*network.tables);

  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto signed_call = create_signed_request(user_caller);
  auto serialized_signed_call = signed_call.build_request();
  auto rpc_ctx =
    enclave::make_rpc_context(user_session, serialized_signed_call);
  auto response = parse_response(frontend.process(rpc_ctx).value());
  CHECK(response.status == HTTP_STATUS_OK);
}

TEST_CASE("Forwarding" * doctest::test_suite("forwarding"))
{
  NetworkState network_primary;

  NetworkState network_backup;
  prepare_callers(network_backup);

  TestForwardingUserFrontEnd user_frontend_primary(*network_primary.tables);
  TestForwardingUserFrontEnd user_frontend_backup(*network_backup.tables);

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto channel_stub = std::make_shared<ChannelStubProxy>();
  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr, ConsensusType::CFT);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto simple_call = create_simple_request();
  auto serialized_call = simple_call.build_request();

  auto backup_ctx =
    enclave::make_rpc_context(backup_user_session, serialized_call);
  auto ctx = enclave::make_rpc_context(user_session, serialized_call);

  {
    INFO("Backup frontend without forwarder does not forward");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(backup_ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(r.value());
    CHECK(response.status == HTTP_STATUS_TEMPORARY_REDIRECT);
  }

  user_frontend_backup.set_cmd_forwarder(backup_forwarder);
  backup_ctx->session->is_forwarding = false;

  {
    INFO("Read command is not forwarded to primary");
    TestUserFrontend user_frontend_backup_read(*network_backup.tables);
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup_read.process(backup_ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(r.value());
    CHECK(response.status == HTTP_STATUS_OK);
  }

  {
    INFO("Write command on backup is forwarded to primary");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(backup_ctx);
    REQUIRE(!r.has_value());
    REQUIRE(channel_stub->size() == 1);

    auto forwarded_msg = channel_stub->get_pop_back();
    auto [fwd_ctx, node_id] =
      backup_forwarder
        ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
        .value();

    {
      INFO("Invalid caller");
      auto response =
        parse_response(user_frontend_primary.process_forwarded(fwd_ctx));
      CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
    };

    prepare_callers(network_primary);

    {
      INFO("Valid caller");
      auto response =
        parse_response(user_frontend_primary.process_forwarded(fwd_ctx));
      CHECK(response.status == HTTP_STATUS_OK);
    }
  }

  {
    INFO("Forwarding write command to a backup returns error");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(backup_ctx);
    REQUIRE(!r.has_value());
    REQUIRE(channel_stub->size() == 1);

    auto forwarded_msg = channel_stub->get_pop_back();
    auto [fwd_ctx, node_id] =
      backup_forwarder
        ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
        .value();

    // Processing forwarded response by a backup frontend (here, the same
    // frontend that the command was originally issued to)
    auto response =
      parse_response(user_frontend_backup.process_forwarded(fwd_ctx));

    CHECK(response.status == HTTP_STATUS_TEMPORARY_REDIRECT);
  }

  {
    // A write was executed on this frontend (above), so reads must be
    // forwarded too for session consistency
    INFO("Read command is now forwarded to primary on this session");
    TestUserFrontend user_frontend_backup_read(*network_backup.tables);
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup_read.process(backup_ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(r.value());
    CHECK(response.status == HTTP_STATUS_TEMPORARY_REDIRECT);
  }

  {
    INFO("Client signature on forwarded RPC is recorded by primary");

    REQUIRE(channel_stub->is_empty());
    auto signed_call = create_signed_request(user_caller);
    auto serialized_signed_call = signed_call.build_request();
    auto signed_ctx =
      enclave::make_rpc_context(user_session, serialized_signed_call);
    const auto r = user_frontend_backup.process(signed_ctx);
    REQUIRE(!r.has_value());
    REQUIRE(channel_stub->size() == 1);

    auto forwarded_msg = channel_stub->get_pop_back();
    auto [fwd_ctx, node_id] =
      backup_forwarder
        ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
        .value();

    auto response =
      parse_response(user_frontend_primary.process_forwarded(fwd_ctx));
    CHECK(response.status == HTTP_STATUS_OK);
  }

  // On a session that was previously forwarded, and is now primary,
  // commands should still succeed
  ctx->session->is_forwarding = true;
  {
    INFO("Write command primary on a forwarded session succeeds");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_primary.process(ctx);
    CHECK(r.has_value());
    auto response = parse_response(r.value());
    CHECK(response.status == HTTP_STATUS_OK);
  }
}

TEST_CASE("Nodefrontend forwarding" * doctest::test_suite("forwarding"))
{
  NetworkState network_primary;
  prepare_callers(network_primary);

  NetworkState network_backup;
  prepare_callers(network_backup);

  ShareManager share_manager(network_primary);
  StubNodeState stub_node;

  TestForwardingNodeFrontEnd node_frontend_primary(network_primary, stub_node);
  TestForwardingNodeFrontEnd node_frontend_backup(network_backup, stub_node);

  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr, ConsensusType::CFT);
  node_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto node_session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, node_caller.raw());
  auto ctx = enclave::make_rpc_context(node_session, serialized_call);
  const auto r = node_frontend_backup.process(ctx);
  REQUIRE(!r.has_value());
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto [fwd_ctx, node_id] =
    backup_forwarder
      ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
      .value();

  auto response =
    parse_response(node_frontend_primary.process_forwarded(fwd_ctx));
  CHECK(response.status == HTTP_STATUS_OK);

  CHECK(node_frontend_primary.last_caller_cert == node_caller);
  CHECK(node_frontend_primary.last_caller_id == INVALID_ID);
}

TEST_CASE("Userfrontend forwarding" * doctest::test_suite("forwarding"))
{
  NetworkState network_primary;
  prepare_callers(network_primary);

  NetworkState network_backup;
  prepare_callers(network_backup);

  TestForwardingUserFrontEnd user_frontend_primary(*network_primary.tables);
  TestForwardingUserFrontEnd user_frontend_backup(*network_backup.tables);

  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr, ConsensusType::CFT);
  user_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto ctx = enclave::make_rpc_context(user_session, serialized_call);
  const auto r = user_frontend_backup.process(ctx);
  REQUIRE(!r.has_value());
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto [fwd_ctx, node_id] =
    backup_forwarder
      ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
      .value();

  auto response =
    parse_response(user_frontend_primary.process_forwarded(fwd_ctx));
  CHECK(response.status == HTTP_STATUS_OK);

  CHECK(user_frontend_primary.last_caller_cert == user_caller);
  CHECK(user_frontend_primary.last_caller_id == 0);
}

TEST_CASE("Memberfrontend forwarding" * doctest::test_suite("forwarding"))
{
  NetworkState network_primary;
  prepare_callers(network_primary);

  NetworkState network_backup;
  prepare_callers(network_backup);

  ShareManager share_manager(network_primary);
  StubNodeState stub_node;

  TestForwardingMemberFrontEnd member_frontend_primary(
    *network_primary.tables, network_primary, stub_node, share_manager);
  TestForwardingMemberFrontEnd member_frontend_backup(
    *network_backup.tables, network_backup, stub_node, share_manager);
  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr, ConsensusType::CFT);
  member_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto ctx = enclave::make_rpc_context(member_session, serialized_call);
  const auto r = member_frontend_backup.process(ctx);
  REQUIRE(!r.has_value());
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto [fwd_ctx, node_id] =
    backup_forwarder
      ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
      .value();

  auto response =
    parse_response(member_frontend_primary.process_forwarded(fwd_ctx));
  CHECK(response.status == HTTP_STATUS_OK);

  CHECK(member_frontend_primary.last_caller_cert == member_caller);
  CHECK(member_frontend_primary.last_caller_id == 0);
}

class TestConflictFrontend : public BaseTestFrontend
{
public:
  using Values = kv::Map<size_t, size_t>;

  TestConflictFrontend(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto conflict_once = [this](auto& args) {
      static bool conflict_next = true;
      if (conflict_next)
      {
        // Warning: Never do this in a real application!
        // Create another transaction that conflicts with the frontend one
        auto tx = this->tables.create_tx();
        auto conflict_map = tx.template rw<Values>("test_values_conflict");
        conflict_map->put(0, 42);
        REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
        conflict_next = false;
      }

      auto conflict_map = args.tx.template rw<Values>("test_values_conflict");
      conflict_map->get(0); // Record a read dependency
      conflict_map->put(0, 0);

      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("conflict_once", HTTP_POST, conflict_once).install();
  }
};

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
