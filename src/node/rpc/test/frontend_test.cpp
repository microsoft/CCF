// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#include "consensus/pbft/pbft_requests.h"
#include "consensus/test/stub_consensus.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "node/encryptor.h"
#include "node/entities.h"
#include "node/genesis_gen.h"
#include "node/history.h"
#include "node/network_state.h"
#include "node/rpc/json_handler.h"
#include "node/rpc/json_rpc.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/user_frontend.h"
#include "node/test/channel_stub.h"
#include "node_stub.h"

#include <doctest/doctest.h>
#include <iostream>
#include <string>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

using namespace ccfapp;
using namespace ccf;
using namespace std;

static constexpr auto default_pack = jsonrpc::Pack::MsgPack;

class TestUserFrontend : public SimpleUserRpcFrontend
{
public:
  TestUserFrontend(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install("empty_function", empty_function, HandlerRegistry::Read);

    auto empty_function_signed = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install(
      "empty_function_signed", empty_function_signed, HandlerRegistry::Read)
      .set_require_client_signature(true);

    auto empty_function_no_auth = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install(
      "empty_function_no_auth", empty_function_no_auth, HandlerRegistry::Read)
      .set_require_client_identity(false);
  }
};

class TestReqNotStoredFrontend : public SimpleUserRpcFrontend
{
public:
  TestReqNotStoredFrontend(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install("empty_function", empty_function, HandlerRegistry::Read);
    disable_request_storing();
  }
};

class TestMinimalHandleFunction : public SimpleUserRpcFrontend
{
public:
  TestMinimalHandleFunction(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto echo_function = [this](Store::Tx& tx, nlohmann::json&& params) {
      return make_success(std::move(params));
    };
    install("echo", json_adapter(echo_function), HandlerRegistry::Read);

    auto get_caller_function =
      [this](Store::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
        return make_success(caller_id);
      };
    install(
      "get_caller", json_adapter(get_caller_function), HandlerRegistry::Read);

    auto failable_function =
      [this](Store::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
        const auto it = params.find("error");
        if (it != params.end())
        {
          const http_status error_code = (*it)["code"];
          const std::string error_msg = (*it)["message"];

          return make_error((http_status)error_code, error_msg);
        }

        return make_success(true);
      };
    install("failable", json_adapter(failable_function), HandlerRegistry::Read);
  }
};

class TestRestrictedVerbsFrontend : public SimpleUserRpcFrontend
{
public:
  TestRestrictedVerbsFrontend(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto get_only = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install("get_only", get_only, HandlerRegistry::Read).set_http_get_only();

    auto post_only = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install("post_only", post_only, HandlerRegistry::Read).set_http_post_only();

    auto put_or_delete = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install("put_or_delete", put_or_delete, HandlerRegistry::Read)
      .set_allowed_verbs({HTTP_PUT, HTTP_DELETE});
  }
};

class TestExplicitCommitability : public SimpleUserRpcFrontend
{
public:
  Store::Map<size_t, size_t>& values;

  TestExplicitCommitability(Store& tables) :
    SimpleUserRpcFrontend(tables),
    values(tables.create<size_t, size_t>("test_values"))
  {
    open();

    auto maybe_commit = [this](RequestArgs& args) {
      const auto parsed =
        jsonrpc::unpack(args.rpc_ctx->get_request_body(), default_pack);

      const auto new_value = parsed["value"].get<size_t>();
      auto view = args.tx.get_view(values);
      view->put(0, new_value);

      const auto apply_it = parsed.find("apply");
      if (apply_it != parsed.end())
      {
        const auto should_apply = apply_it->get<bool>();
        args.rpc_ctx->set_apply_writes(should_apply);
      }

      const auto status = parsed["status"].get<http_status>();
      args.rpc_ctx->set_response_status(status);
    };
    install("maybe_commit", maybe_commit, HandlerRegistry::Write);
  }
};

class TestMemberFrontend : public MemberRpcFrontend
{
public:
  TestMemberFrontend(ccf::NetworkState& network, ccf::StubNodeState& node) :
    MemberRpcFrontend(network, node)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    member_handlers.install(
      "empty_function", empty_function, HandlerRegistry::Read);
  }
};

class TestNoCertsFrontend : public RpcFrontend
{
  HandlerRegistry handlers;

public:
  TestNoCertsFrontend(Store& tables) :
    RpcFrontend(tables, handlers),
    handlers(tables)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    handlers.install("empty_function", empty_function, HandlerRegistry::Read);
  }
};

//
// User, Node and Member frontends used for forwarding tests
//

class RpcContextRecorder
{
public:
  std::vector<uint8_t> last_caller_cert;
  CallerId last_caller_id;

  void record_ctx(RequestArgs& args)
  {
    last_caller_cert = std::vector<uint8_t>(args.rpc_ctx->session->caller_cert);
    last_caller_id = args.caller_id;
  }
};

class TestForwardingUserFrontEnd : public SimpleUserRpcFrontend,
                                   public RpcContextRecorder
{
public:
  TestForwardingUserFrontEnd(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    install("empty_function", empty_function, HandlerRegistry::Write);

    auto empty_function_no_auth = [this](RequestArgs& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    install(
      "empty_function_no_auth", empty_function_no_auth, HandlerRegistry::Write)
      .set_require_client_identity(false);
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

    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    handlers.install("empty_function", empty_function, HandlerRegistry::Write);
  }
};

class TestForwardingMemberFrontEnd : public MemberRpcFrontend,
                                     public RpcContextRecorder
{
public:
  TestForwardingMemberFrontEnd(
    Store& tables, ccf::NetworkState& network, ccf::StubNodeState& node) :
    MemberRpcFrontend(network, node)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    handlers.install("empty_function", empty_function, HandlerRegistry::Write);
  }
};

// used throughout
auto kp = tls::make_key_pair();
NetworkState network;
NetworkState network2;
auto encryptor = std::make_shared<NullTxEncryptor>();

NetworkState pbft_network(ConsensusType::PBFT);
auto history_kp = tls::make_key_pair();

auto history = std::make_shared<NullTxHistory>(
  *pbft_network.tables,
  0,
  *history_kp,
  pbft_network.signatures,
  pbft_network.nodes);

StubNodeState stub_node;

std::vector<uint8_t> sign_json(nlohmann::json j)
{
  auto contents = nlohmann::json::to_msgpack(j);
  return kp->sign(contents);
}

auto create_simple_request(
  const std::string& method = "empty_function",
  jsonrpc::Pack pack = default_pack)
{
  http::Request request(method);
  request.set_header(
    http::headers::CONTENT_TYPE, details::pack_to_content_type(pack));
  return request;
}

std::pair<http::Request, ccf::SignedReq> create_signed_request(
  const http::Request& r = create_simple_request(),
  const std::vector<uint8_t>* body = nullptr)
{
  http::Request s(r);

  s.set_body(body);

  http::SigningDetails details;
  http::sign_request(s, kp, &details);

  ccf::SignedReq signed_req{details.signature,
                            details.to_sign,
                            body == nullptr ? std::vector<uint8_t>() : *body,
                            MBEDTLS_MD_SHA256};
  return {s, signed_req};
}

http::SimpleResponseProcessor::Response parse_response(const vector<uint8_t>& v)
{
  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  const auto parsed_count = parser.execute(v.data(), v.size());
  REQUIRE(parsed_count == v.size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

nlohmann::json parse_response_body(
  const vector<uint8_t>& body, jsonrpc::Pack pack = default_pack)
{
  return jsonrpc::unpack(body, pack);
}

std::optional<SignedReq> get_signed_req(CallerId caller_id)
{
  Store::Tx tx;
  auto client_sig_view = tx.get_view(network.user_client_signatures);
  return client_sig_view->get(caller_id);
}

// callers used throughout
auto user_caller = kp -> self_sign("CN=name");
auto user_caller_der = tls::make_verifier(user_caller) -> der_cert_data();

auto member_caller = kp -> self_sign("CN=name_member");
auto member_caller_der = tls::make_verifier(member_caller) -> der_cert_data();

auto node_caller = kp -> self_sign("CN=node");
auto node_caller_der = tls::make_verifier(node_caller) -> der_cert_data();

auto nos_caller = kp -> self_sign("CN=nostore_user");
auto nos_caller_der = tls::make_verifier(nos_caller) -> der_cert_data();

auto kp_other = tls::make_key_pair();
auto invalid_caller = kp_other -> self_sign("CN=name");
auto invalid_caller_der = tls::make_verifier(invalid_caller) -> der_cert_data();

auto anonymous_caller_der = std::vector<uint8_t>();

std::vector<uint8_t> dummy_key_share = {1, 2, 3};

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
UserId nos_id = INVALID_ID;

MemberId member_id = INVALID_ID;
MemberId invalid_member_id = INVALID_ID;

void prepare_callers()
{
  // It is necessary to set a consensus before committing the first transaction,
  // so that the KV batching done before calling into replicate() stays in
  // order.

  // First, clear all previous callers since the same callers cannot be added
  // twice to a store
  network.tables->clear();
  auto backup_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  Store::Tx tx;
  network.tables->set_encryptor(encryptor);
  network2.tables->set_encryptor(encryptor);

  GenesisGenerator g(network, tx);
  g.init_values();
  user_id = g.add_user(user_caller);
  nos_id = g.add_user(nos_caller);
  member_id = g.add_member(member_caller, dummy_key_share);
  invalid_member_id = g.add_member(invalid_caller, dummy_key_share);
  CHECK(g.finalize() == kv::CommitSuccess::OK);
}

void add_callers_primary_store()
{
  Store::Tx gen_tx;
  network2.tables->clear();
  GenesisGenerator g(network2, gen_tx);
  g.init_values();
  user_id = g.add_user(user_caller);
  member_id = g.add_member(member_caller, dummy_key_share);
  CHECK(g.finalize() == kv::CommitSuccess::OK);
}

void add_callers_pbft_store()
{
  Store::Tx gen_tx;
  pbft_network.tables->set_encryptor(encryptor);
  pbft_network.tables->clear();
  pbft_network.tables->set_history(history);
  auto backup_consensus =
    std::make_shared<kv::PrimaryStubConsensus>(ConsensusType::PBFT);
  pbft_network.tables->set_consensus(backup_consensus);

  GenesisGenerator g(pbft_network, gen_tx);
  g.init_values();
  user_id = g.add_user(user_caller);
  CHECK(g.finalize() == kv::CommitSuccess::OK);
}

TEST_CASE("process_pbft")
{
  add_callers_pbft_store();
  TestUserFrontend frontend(*pbft_network.tables);
  auto simple_call = create_simple_request();

  const nlohmann::json call_body = {{"foo", "bar"}, {"baz", 42}};
  const auto serialized_body = jsonrpc::pack(call_body, default_pack);
  simple_call.set_body(&serialized_body);

  const auto serialized_call = simple_call.build_request();
  pbft::Request request = {user_id, user_caller_der, serialized_call};

  auto session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, user_id, user_caller_der);
  auto ctx = enclave::make_rpc_context(session, request.raw);
  frontend.process_pbft(ctx);

  Store::Tx tx;
  auto pbft_requests_map = tx.get_view(pbft_network.pbft_requests_map);
  auto request_value = pbft_requests_map->get(0);
  REQUIRE(request_value.has_value());

  pbft::Request deserialised_req = request_value.value();

  REQUIRE(deserialised_req.caller_id == user_id);
  REQUIRE(deserialised_req.caller_cert == user_caller_der);
  REQUIRE(deserialised_req.raw == serialized_call);
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
  prepare_callers();
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

  SUBCASE("handler does not require signature")
  {
    const auto simple_call = create_simple_request();
    const auto [signed_call, signed_req] = create_signed_request(simple_call);
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

      auto signed_resp = get_signed_req(user_id);
      CHECK(!signed_resp.has_value());
    }

    INFO("Signed RPC");
    {
      const auto serialized_response = frontend.process(signed_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);

      auto signed_resp = get_signed_req(user_id);
      REQUIRE(signed_resp.has_value());
      auto value = signed_resp.value();
      CHECK(value == signed_req);
    }
  }

  SUBCASE("handler requires signature")
  {
    const auto simple_call = create_simple_request("empty_function_signed");
    const auto [signed_call, signed_req] = create_signed_request(simple_call);
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
      CHECK(error_msg.find("RPC must be signed") != std::string::npos);

      auto signed_resp = get_signed_req(user_id);
      CHECK(!signed_resp.has_value());
    }

    INFO("Signed RPC");
    {
      const auto serialized_response = frontend.process(signed_rpc_ctx).value();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);

      auto signed_resp = get_signed_req(user_id);
      REQUIRE(signed_resp.has_value());
      auto value = signed_resp.value();
      CHECK(value == signed_req);
    }
  }

  SUBCASE("request with signature but do not store")
  {
    TestReqNotStoredFrontend frontend_nostore(*network.tables);
    const auto simple_call = create_simple_request("empty_function");
    const auto [signed_call, signed_req] = create_signed_request(simple_call);
    const auto serialized_signed_call = signed_call.build_request();
    auto signed_rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_signed_call);

    const auto serialized_response =
      frontend_nostore.process(signed_rpc_ctx).value();
    const auto response = parse_response(serialized_response);
    REQUIRE(response.status == HTTP_STATUS_OK);

    auto signed_resp = get_signed_req(user_id);
    REQUIRE(signed_resp.has_value());
    auto value = signed_resp.value();
    CHECK(value.req.empty());
    CHECK(value.sig == signed_req.sig);
  }
}

TEST_CASE("process with caller")
{
  prepare_callers();
  TestUserFrontend frontend(*network.tables);

  SUBCASE("handler does not require valid caller")
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

  SUBCASE("handler requires valid caller")
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
      REQUIRE(response.status == HTTP_STATUS_FORBIDDEN);
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
      REQUIRE(response.status == HTTP_STATUS_FORBIDDEN);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(
        error_msg.find("Could not find matching user certificate") !=
        std::string::npos);
    }
  }
}

TEST_CASE("No certs table")
{
  prepare_callers();
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
  prepare_callers();
  auto simple_call = create_simple_request();
  std::vector<uint8_t> serialized_call = simple_call.build_request();
  TestMemberFrontend frontend(network, stub_node);

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
    CHECK(response.status == HTTP_STATUS_FORBIDDEN);
  }
}

TEST_CASE("MinimalHandleFunction")
{
  prepare_callers();
  TestMinimalHandleFunction frontend(*network.tables);
  for (const auto pack_type : {jsonrpc::Pack::Text, jsonrpc::Pack::MsgPack})
  {
    {
      INFO("Calling echo, with params in body");
      auto echo_call = create_simple_request("echo", pack_type);
      const nlohmann::json j_body = {{"data", {"nested", "Some string"}},
                                     {"other", "Another string"}};
      const auto serialized_body = jsonrpc::pack(j_body, pack_type);

      auto [signed_call, signed_req] =
        create_signed_request(echo_call, &serialized_body);
      const auto serialized_call = signed_call.build_request();

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
      auto get_caller = create_simple_request("get_caller", pack_type);

      const auto [signed_call, signed_req] = create_signed_request(get_caller);
      const auto serialized_call = signed_call.build_request();

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

    const auto [signed_call, signed_req] = create_signed_request(dont_fail);
    const auto serialized_call = signed_call.build_request();

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
      const auto serialized_body = jsonrpc::pack(j_body, default_pack);

      const auto [signed_call, signed_req] =
        create_signed_request(fail, &serialized_body);
      const auto serialized_call = signed_call.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response = parse_response(frontend.process(rpc_ctx).value());
      CHECK(response.status == err);
      CHECK(
        response.headers[http::headers::CONTENT_TYPE] ==
        http::headervalues::contenttype::TEXT);
      const std::string body_s(response.body.begin(), response.body.end());
      CHECK(body_s == msg);
    }
  }
}

TEST_CASE("Restricted verbs")
{
  prepare_callers();
  TestRestrictedVerbsFrontend frontend(*network.tables);

  for (auto verb = HTTP_DELETE; verb <= HTTP_SOURCE;
       verb = (http_method)(size_t(verb) + 1))
  {
    INFO(http_method_str(verb));

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
        CHECK(v.find(http_method_str(HTTP_GET)) != std::string::npos);
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
        CHECK(v.find(http_method_str(HTTP_POST)) != std::string::npos);
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
        CHECK(v.find(http_method_str(HTTP_PUT)) != std::string::npos);
        CHECK(v.find(http_method_str(HTTP_DELETE)) != std::string::npos);
        CHECK(v.find(http_method_str(verb)) == std::string::npos);
      }
    }
  }
}

TEST_CASE("Explicit commitability")
{
  prepare_callers();
  TestExplicitCommitability frontend(*network.tables);

#define XX(num, name, string) HTTP_STATUS_##name,
  std::vector<http_status> all_statuses = {HTTP_STATUS_MAP(XX)};
#undef XX

  size_t next_value = 0;

  auto get_value = [&]() {
    Store::Tx tx;
    auto view = tx.get_view(frontend.values);
    auto actual_v = view->get(0).value();
    return actual_v;
  };

  // Set initial value
  {
    Store::Tx tx;
    tx.get_view(frontend.values)->put(0, next_value);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
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
      const auto serialized_body = jsonrpc::pack(request_body, default_pack);
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
        const auto serialized_body = jsonrpc::pack(request_body, default_pack);
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

TEST_CASE("Signed read requests can be executed on backup")
{
  prepare_callers();

  TestUserFrontend frontend(*network.tables);

  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto [signed_call, signed_req] = create_signed_request();
  auto serialized_signed_call = signed_call.build_request();
  auto rpc_ctx =
    enclave::make_rpc_context(user_session, serialized_signed_call);
  auto response = parse_response(frontend.process(rpc_ctx).value());
  CHECK(response.status == HTTP_STATUS_OK);
}

TEST_CASE("Forwarding" * doctest::test_suite("forwarding"))
{
  prepare_callers();

  TestForwardingUserFrontEnd user_frontend_backup(*network.tables);
  TestForwardingUserFrontEnd user_frontend_primary(*network2.tables);

  auto channel_stub = std::make_shared<ChannelStubProxy>();
  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network2.tables->set_consensus(primary_consensus);

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
    TestUserFrontend user_frontend_backup_read(*network.tables);
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
      CHECK(response.status == HTTP_STATUS_FORBIDDEN);
    };

    {
      INFO("Valid caller");
      add_callers_primary_store();
      auto response =
        parse_response(user_frontend_primary.process_forwarded(fwd_ctx));
      CHECK(response.status == HTTP_STATUS_OK);
    }
  }

  {
    INFO("Unauthenticated handler");
    auto simple_call_no_auth = create_simple_request("empty_function_no_auth");
    auto serialized_call_no_auth = simple_call_no_auth.build_request();

    REQUIRE(channel_stub->is_empty());

    {
      INFO("Known caller");
      auto ctx =
        enclave::make_rpc_context(user_session, serialized_call_no_auth);

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

      CHECK(user_frontend_primary.last_caller_cert == user_caller_der);
      CHECK(user_frontend_primary.last_caller_id == 0);
    }

    {
      INFO("Unknown caller");
      auto ctx =
        enclave::make_rpc_context(invalid_session, serialized_call_no_auth);

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

      CHECK(user_frontend_primary.last_caller_cert == invalid_caller_der);
      CHECK(user_frontend_primary.last_caller_id == INVALID_ID);
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
    TestUserFrontend user_frontend_backup_read(*network.tables);
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
    auto [signed_call, signed_req] = create_signed_request();
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

    user_frontend_primary.process_forwarded(fwd_ctx);

    Store::Tx tx;
    auto client_sig_view = tx.get_view(network2.user_client_signatures);
    auto client_sig = client_sig_view->get(user_id);
    REQUIRE(client_sig.has_value());
    REQUIRE(client_sig.value() == signed_req);
  }

  // On a session that was previously forwarded, and is now primary,
  // commands should still succeed
  ctx->session->is_forwarding = true;
  {
    INFO("Write command primary on a forwarded session succeeds");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_primary.process(ctx);
    CHECK(r.has_value());
    add_callers_primary_store();
    auto response = parse_response(r.value());
    CHECK(response.status == HTTP_STATUS_OK);
  }
}

TEST_CASE("Nodefrontend forwarding" * doctest::test_suite("forwarding"))
{
  prepare_callers();

  TestForwardingNodeFrontEnd node_frontend_backup(network, stub_node);
  TestForwardingNodeFrontEnd node_frontend_primary(network2, stub_node);
  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr);
  node_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network2.tables->set_consensus(primary_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto node_session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, node_caller);
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
  prepare_callers();
  add_callers_primary_store();

  TestForwardingUserFrontEnd user_frontend_backup(*network.tables);
  TestForwardingUserFrontEnd user_frontend_primary(*network2.tables);
  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr);
  user_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network2.tables->set_consensus(primary_consensus);

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

  CHECK(user_frontend_primary.last_caller_cert == user_caller_der);
  CHECK(user_frontend_primary.last_caller_id == 0);
}

TEST_CASE("Memberfrontend forwarding" * doctest::test_suite("forwarding"))
{
  prepare_callers();
  add_callers_primary_store();

  TestForwardingMemberFrontEnd member_frontend_backup(
    *network.tables, network, stub_node);
  TestForwardingMemberFrontEnd member_frontend_primary(
    *network2.tables, network2, stub_node);
  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    nullptr, channel_stub, nullptr);
  member_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto primary_consensus = std::make_shared<kv::PrimaryStubConsensus>();
  network2.tables->set_consensus(primary_consensus);

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

  CHECK(member_frontend_primary.last_caller_cert == member_caller_der);
  CHECK(member_frontend_primary.last_caller_id == 0);
}

// We need an explicit main to initialize kremlib and EverCrypt
int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  ::EverCrypt_AutoConfig2_init();
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
