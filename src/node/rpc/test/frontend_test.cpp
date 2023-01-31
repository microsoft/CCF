// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/tx.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include "ccf/app_interface.h"
#include "ccf/ds/logger.h"
#include "ccf/json_handler.h"
#include "ccf/kv/map.h"
#include "ccf/serdes.h"
#include "consensus/aft/request.h"
#include "ds/files.h"
#include "enclave/enclave_time.h"
#include "frontend_test_infra.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/network_state.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/node_frontend.h"
#include "node/test/channel_stub.h"
#include "node_stub.h"
#include "service/genesis_gen.h"

#include <doctest/doctest.h>
#include <iostream>
#include <string>

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

using namespace ccf;
using namespace std;

class SimpleUserRpcFrontend : public RpcFrontend
{
protected:
  UserEndpointRegistry common_handlers;

public:
  SimpleUserRpcFrontend(
    kv::Store& tables, ccfapp::AbstractNodeContext& context) :
    RpcFrontend(tables, common_handlers, context),
    common_handlers(context)
  {}
};

class BaseTestFrontend : public SimpleUserRpcFrontend
{
public:
  ccf::StubNodeContext context;

  BaseTestFrontend(kv::Store& tables) : SimpleUserRpcFrontend(tables, context)
  {}

  // For testing only, we don't need to specify auth policies everywhere and
  // default to no auth
  ccf::endpoints::Endpoint make_endpoint(
    const std::string& method,
    RESTVerb verb,
    const ccf::endpoints::EndpointFunction& f,
    const ccf::AuthnPolicies& ap = no_auth_required)
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

    auto empty_function = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint(
      "/empty_function", HTTP_POST, empty_function, {user_cert_auth_policy})
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Sometimes)
      .install();

    auto empty_function_signed = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint(
      "/empty_function_signed",
      HTTP_POST,
      empty_function_signed,
      {user_signature_auth_policy})
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Sometimes)
      .install();

    auto empty_function_no_auth = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint(
      "/empty_function_no_auth",
      HTTP_POST,
      empty_function_no_auth,
      no_auth_required)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Sometimes)
      .install();
  }
};

class TestJsonWrappedEndpointFunction : public BaseTestFrontend
{
public:
  TestJsonWrappedEndpointFunction(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto echo_function = [this](auto& ctx, nlohmann::json&& params) {
      return make_success(std::move(params));
    };
    make_endpoint("/echo", HTTP_POST, json_adapter(echo_function)).install();

    auto echo_query_function = [this](auto& ctx, nlohmann::json&&) {
      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());
      return make_success(std::move(parsed_query));
    };
    make_endpoint(
      "/echo_parsed_query", HTTP_POST, json_adapter(echo_query_function))
      .install();

    auto get_caller_function = [this](auto& ctx, nlohmann::json&&) {
      const auto& ident = ctx.template get_caller<UserCertAuthnIdentity>();
      return make_success(ident.user_id);
    };
    make_endpoint(
      "/get_caller",
      HTTP_POST,
      json_adapter(get_caller_function),
      {user_cert_auth_policy})
      .install();

    auto failable_function = [this](auto& ctx, nlohmann::json&& params) {
      const auto it = params.find("error");
      if (it != params.end())
      {
        const http_status error_code = (*it)["code"];
        const std::string error_msg = (*it)["message"];

        return make_error((http_status)error_code, "Error", error_msg);
      }

      return make_success(true);
    };
    make_endpoint("/failable", HTTP_POST, json_adapter(failable_function))
      .install();
  }
};

class TestRestrictedVerbsFrontend : public BaseTestFrontend
{
public:
  TestRestrictedVerbsFrontend(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto get_only = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/get_only", HTTP_GET, get_only).install();

    auto post_only = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/post_only", HTTP_POST, post_only).install();

    auto put_or_delete = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/put_or_delete", HTTP_PUT, put_or_delete).install();
    make_endpoint("/put_or_delete", HTTP_DELETE, put_or_delete).install();
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

    auto maybe_commit = [this](ccf::endpoints::EndpointContext& ctx) {
      const auto parsed =
        serdes::unpack(ctx.rpc_ctx->get_request_body(), default_pack);

      const auto new_value = parsed["value"].get<size_t>();
      auto vs = ctx.tx.rw(values);
      vs->put(0, new_value);

      const auto apply_it = parsed.find("apply");
      if (apply_it != parsed.end())
      {
        const auto should_apply = apply_it->get<bool>();
        ctx.rpc_ctx->set_apply_writes(should_apply);
      }

      const auto status = parsed["status"].get<http_status>();
      ctx.rpc_ctx->set_response_status(status);
    };
    make_endpoint("/maybe_commit", HTTP_POST, maybe_commit).install();
  }
};

class TestAlternativeHandlerTypes : public BaseTestFrontend
{
public:
  TestAlternativeHandlerTypes(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto command = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    endpoints
      .make_command_endpoint("/command", HTTP_POST, command, no_auth_required)
      .install();

    auto read_only = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    endpoints
      .make_read_only_endpoint(
        "/read_only", HTTP_POST, read_only, no_auth_required)
      .install();
    endpoints
      .make_read_only_endpoint(
        "/read_only", HTTP_GET, read_only, no_auth_required)
      .install();
  }
};

class TestTemplatedPaths : public BaseTestFrontend
{
public:
  TestTemplatedPaths(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto endpoint = [this](auto& ctx) {
      nlohmann::json response_body = ctx.rpc_ctx->get_request_path_params();
      ctx.rpc_ctx->set_response_body(response_body.dump(2));
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/{foo}/{bar}/{baz}", HTTP_POST, endpoint).install();
  }
};

class TestDecodedTemplatedPaths : public BaseTestFrontend
{
public:
  TestDecodedTemplatedPaths(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto endpoint = [this](auto& ctx) {
      nlohmann::json response_body =
        ctx.rpc_ctx->get_decoded_request_path_params();
      ctx.rpc_ctx->set_response_body(response_body.dump(2));
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/{foo}/{bar}/{baz}", HTTP_POST, endpoint).install();
  }
};

class TestMemberFrontend : public MemberRpcFrontend
{
public:
  TestMemberFrontend(
    ccf::NetworkState& network,
    ccf::StubNodeContext& context,
    ccf::ShareManager& share_manager) :
    MemberRpcFrontend(network, context, share_manager)
  {
    open();

    auto empty_function = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    member_endpoints
      .make_endpoint(
        "/empty_function", HTTP_POST, empty_function, {member_cert_auth_policy})
      .set_forwarding_required(endpoints::ForwardingRequired::Sometimes)
      .install();
  }
};

class TestNoCertsFrontend : public RpcFrontend
{
  ccf::StubNodeContext context;
  ccf::endpoints::EndpointRegistry endpoints;

public:
  TestNoCertsFrontend(kv::Store& tables) :
    RpcFrontend(tables, endpoints, context),
    endpoints("test")
  {
    open();

    auto empty_function = [this](auto& ctx) {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    endpoints
      .make_endpoint(
        "/empty_function", HTTP_POST, empty_function, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Sometimes)
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
  crypto::Pem last_caller_cert;
  std::optional<std::string> last_caller_id = std::nullopt;

  void record_ctx(ccf::endpoints::EndpointContext& ctx)
  {
    last_caller_cert =
      crypto::cert_der_to_pem(ctx.rpc_ctx->get_session_context()->caller_cert);
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
      last_caller_id.reset();
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

    auto empty_function = [this](auto& ctx) {
      record_ctx(ctx);
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    make_endpoint(
      "/empty_function", HTTP_POST, empty_function, {user_cert_auth_policy})
      .install();

    auto empty_function_no_auth = [this](auto& ctx) {
      record_ctx(ctx);
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/empty_function_no_auth", HTTP_POST, empty_function_no_auth)
      .install();
  }
};

class TestForwardingNodeFrontEnd : public NodeRpcFrontend,
                                   public RpcContextRecorder
{
public:
  TestForwardingNodeFrontEnd(
    ccf::NetworkState& network, ccf::StubNodeContext& context) :
    NodeRpcFrontend(network, context)
  {
    open();

    auto empty_function = [this](auto& ctx) {
      record_ctx(ctx);
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    endpoints
      .make_endpoint(
        "/empty_function", HTTP_POST, empty_function, no_auth_required)
      .install();
  }
};

class TestForwardingMemberFrontEnd : public MemberRpcFrontend,
                                     public RpcContextRecorder
{
public:
  TestForwardingMemberFrontEnd(
    ccf::NetworkState& network,
    ccf::StubNodeContext& context,
    ccf::ShareManager& share_manager) :
    MemberRpcFrontend(network, context, share_manager)
  {
    open();

    auto empty_function = [this](auto& ctx) {
      record_ctx(ctx);
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    endpoints
      .make_endpoint(
        "/empty_function", HTTP_POST, empty_function, {member_cert_auth_policy})
      .install();
  }
};

auto create_simple_request(
  const std::string& method = "/empty_function",
  serdes::Pack pack = default_pack)
{
  http::Request request(method);
  request.set_header(
    http::headers::CONTENT_TYPE, ccf::jsonhandler::pack_to_content_type(pack));
  return request;
}

http::Request create_signed_request(
  const crypto::Pem& caller_cert,
  const http::Request& r = create_simple_request(),
  const std::vector<uint8_t>* body = nullptr)
{
  http::Request s(r);

  s.set_body(body);

  auto caller_cert_der = crypto::cert_pem_to_der(caller_cert);
  const auto key_id = crypto::Sha256Hash(caller_cert_der).hex_str();

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
auto user_caller = kp -> self_sign("CN=name", valid_from, valid_to);
auto user_caller_der = crypto::make_verifier(user_caller) -> cert_der();

auto member_caller_der = crypto::make_verifier(member_cert) -> cert_der();

auto node_caller = kp -> self_sign("CN=node", valid_from, valid_to);
auto node_caller_der = crypto::make_verifier(node_caller) -> cert_der();

auto kp_other = crypto::make_key_pair();
auto invalid_caller = kp_other -> self_sign("CN=name", valid_from, valid_to);
auto invalid_caller_der = crypto::make_verifier(invalid_caller) -> cert_der();

auto anonymous_caller_der = std::vector<uint8_t>();

auto user_session =
  make_shared<ccf::SessionContext>(ccf::InvalidSessionId, user_caller_der);
auto backup_user_session =
  make_shared<ccf::SessionContext>(ccf::InvalidSessionId, user_caller_der);
auto invalid_session =
  make_shared<ccf::SessionContext>(ccf::InvalidSessionId, invalid_caller_der);
auto member_session =
  make_shared<ccf::SessionContext>(ccf::InvalidSessionId, member_caller_der);
auto anonymous_session =
  make_shared<ccf::SessionContext>(ccf::InvalidSessionId, anonymous_caller_der);

UserId user_id;

MemberId member_id;
MemberId invalid_member_id;

void prepare_callers(NetworkState& network)
{
  // It is necessary to set a consensus before committing the first transaction,
  // so that the KV batching done before calling into replicate() stays in
  // order.
  auto backup_consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto tx = network.tables->create_tx();
  network.tables->set_encryptor(encryptor);

  init_network(network);

  GenesisGenerator g(network, tx);
  g.create_service(network.identity->cert, ccf::TxID{});
  user_id = g.add_user({user_caller});
  member_id = g.add_member(member_cert);
  invalid_member_id = g.add_member(invalid_caller);
  CHECK(tx.commit() == kv::CommitResult::SUCCESS);
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
    for (const std::string& rpc_name :
         {"", "/", "/this_rpc_doesnt_exist", "/this/rpc/doesnt/exist"})
    {
      const auto invalid_call = create_simple_request(rpc_name);
      const auto serialized_call = invalid_call.build_request();
      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);

      frontend.process(rpc_ctx);
      const auto serialized_response = rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_NOT_FOUND);
    }
  }

  SUBCASE("endpoint does not require signature")
  {
    const auto simple_call = create_simple_request();
    const auto signed_call = create_signed_request(user_caller, simple_call);
    const auto serialized_simple_call = simple_call.build_request();
    const auto serialized_signed_call = signed_call.build_request();

    auto simple_rpc_ctx =
      ccf::make_rpc_context(user_session, serialized_simple_call);
    auto signed_rpc_ctx =
      ccf::make_rpc_context(user_session, serialized_signed_call);

    INFO("Unsigned RPC");
    {
      frontend.process(simple_rpc_ctx);
      const auto serialized_response = simple_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Signed RPC");
    {
      frontend.process(signed_rpc_ctx);
      const auto serialized_response = signed_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }
  }

  SUBCASE("endpoint requires signature")
  {
    const auto simple_call = create_simple_request("/empty_function_signed");
    const auto signed_call = create_signed_request(user_caller, simple_call);
    const auto serialized_simple_call = simple_call.build_request();
    const auto serialized_signed_call = signed_call.build_request();

    auto simple_rpc_ctx =
      ccf::make_rpc_context(user_session, serialized_simple_call);
    auto signed_rpc_ctx =
      ccf::make_rpc_context(user_session, serialized_signed_call);

    INFO("Unsigned RPC");
    {
      frontend.process(simple_rpc_ctx);
      const auto serialized_response = simple_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);

      CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(error_msg.find("Missing signature") != std::string::npos);
    }

    INFO("Signed RPC");
    {
      frontend.process(signed_rpc_ctx);
      const auto serialized_response = signed_rpc_ctx->serialise_response();
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
    const auto simple_call = create_simple_request("/empty_function_no_auth");
    const auto serialized_simple_call = simple_call.build_request();
    auto authenticated_rpc_ctx =
      ccf::make_rpc_context(user_session, serialized_simple_call);
    auto invalid_rpc_ctx =
      ccf::make_rpc_context(invalid_session, serialized_simple_call);
    auto anonymous_rpc_ctx =
      ccf::make_rpc_context(anonymous_session, serialized_simple_call);

    INFO("Valid authentication");
    {
      frontend.process(authenticated_rpc_ctx);
      const auto serialized_response =
        authenticated_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);

      // Even though the RPC does not require authenticated caller, an
      // authenticated RPC succeeds
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Invalid authentication");
    {
      frontend.process(invalid_rpc_ctx);
      const auto serialized_response = invalid_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Anonymous caller");
    {
      frontend.process(anonymous_rpc_ctx);
      const auto serialized_response = anonymous_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }
  }

  SUBCASE("endpoint requires valid caller")
  {
    const auto simple_call = create_simple_request("/empty_function");
    const auto serialized_simple_call = simple_call.build_request();
    auto authenticated_rpc_ctx =
      ccf::make_rpc_context(user_session, serialized_simple_call);
    auto invalid_rpc_ctx =
      ccf::make_rpc_context(invalid_session, serialized_simple_call);
    auto anonymous_rpc_ctx =
      ccf::make_rpc_context(anonymous_session, serialized_simple_call);

    INFO("Valid authentication");
    {
      frontend.process(authenticated_rpc_ctx);
      const auto serialized_response =
        authenticated_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_OK);
    }

    INFO("Invalid authentication");
    {
      frontend.process(invalid_rpc_ctx);
      const auto serialized_response = invalid_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_UNAUTHORIZED);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(
        error_msg.find("Could not find matching user certificate") !=
        std::string::npos);
    }

    INFO("Anonymous caller");
    {
      frontend.process(anonymous_rpc_ctx);
      const auto serialized_response = anonymous_rpc_ctx->serialise_response();
      auto response = parse_response(serialized_response);
      REQUIRE(response.status == HTTP_STATUS_UNAUTHORIZED);
      const std::string error_msg(response.body.begin(), response.body.end());
      CHECK(error_msg.find("No caller user certificate") != std::string::npos);
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
    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
    frontend.process(rpc_ctx);
    const auto serialized_response = rpc_ctx->serialise_response();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_OK);
  }

  INFO("Anonymous caller");
  {
    auto rpc_ctx = ccf::make_rpc_context(anonymous_session, serialized_call);
    frontend.process(rpc_ctx);
    const auto serialized_response = rpc_ctx->serialise_response();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_OK);
  }
}

TEST_CASE("Member caller")
{
  NetworkState network;
  prepare_callers(network);

  ShareManager share_manager(network);
  StubNodeContext context;

  auto simple_call = create_simple_request();
  std::vector<uint8_t> serialized_call = simple_call.build_request();
  TestMemberFrontend frontend(network, context, share_manager);

  SUBCASE("valid caller")
  {
    auto member_rpc_ctx =
      ccf::make_rpc_context(member_session, serialized_call);
    frontend.process(member_rpc_ctx);
    const auto serialized_response = member_rpc_ctx->serialise_response();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_OK);
  }

  SUBCASE("invalid caller")
  {
    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
    frontend.process(rpc_ctx);
    const auto serialized_response = rpc_ctx->serialise_response();
    auto response = parse_response(serialized_response);
    CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
  }
}

TEST_CASE("JsonWrappedEndpointFunction")
{
  NetworkState network;
  prepare_callers(network);
  TestJsonWrappedEndpointFunction frontend(*network.tables);
  for (const auto pack_type : {serdes::Pack::Text, serdes::Pack::MsgPack})
  {
    {
      INFO("Calling echo, with params in body");
      auto echo_call = create_simple_request("/echo", pack_type);
      const nlohmann::json j_body = {
        {"data", {"nested", "Some string"}}, {"other", "Another string"}};
      const auto serialized_body = serdes::pack(j_body, pack_type);
      echo_call.set_body(serialized_body.data(), serialized_body.size());
      const auto serialized_call = echo_call.build_request();

      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
      frontend.process(rpc_ctx);
      auto response = parse_response(rpc_ctx->serialise_response());
      CHECK(response.status == HTTP_STATUS_OK);

      const auto response_body = parse_response_body(response.body, pack_type);
      CHECK(response_body == j_body);
    }

    {
      INFO("Calling echo_query, with params in query");
      auto echo_call = create_simple_request("/echo_parsed_query", pack_type);
      const std::map<std::string, std::string> query_params = {
        {"foo", "helloworld"},
        {"bar", "1"},
        {"fooz", "\"2\""},
        {"baz", "\"awkward\"\"escapes"}};
      for (const auto& [k, v] : query_params)
      {
        echo_call.set_query_param(k, v);
      }

      const auto serialized_call = echo_call.build_request();

      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
      frontend.process(rpc_ctx);
      auto response = parse_response(rpc_ctx->serialise_response());
      CHECK(response.status == HTTP_STATUS_OK);

      const auto response_body = parse_response_body(response.body, pack_type);
      const auto response_map = response_body.get<decltype(query_params)>();
      CHECK(response_map == query_params);
    }

    {
      INFO("Calling get_caller");
      const auto get_caller = create_simple_request("/get_caller", pack_type);
      const auto serialized_call = get_caller.build_request();

      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
      frontend.process(rpc_ctx);
      auto response = parse_response(rpc_ctx->serialise_response());
      CHECK(response.status == HTTP_STATUS_OK);

      const auto response_body = parse_response_body(response.body, pack_type);
      CHECK(response_body == user_id);
    }
  }

  {
    INFO("Calling failable, without failing");
    auto dont_fail = create_simple_request("/failable");
    const auto serialized_call = dont_fail.build_request();

    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
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
      auto fail = create_simple_request("/failable");
      const nlohmann::json j_body = {
        {"error", {{"code", err}, {"message", msg}}}};
      const auto serialized_body = serdes::pack(j_body, default_pack);
      fail.set_body(serialized_body.data(), serialized_body.size());
      const auto serialized_call = fail.build_request();

      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
      frontend.process(rpc_ctx);
      auto response = parse_response(rpc_ctx->serialise_response());
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

    const auto other_verb_status = verb == HTTP_OPTIONS ?
      HTTP_STATUS_NO_CONTENT :
      HTTP_STATUS_METHOD_NOT_ALLOWED;

    {
      http::Request get("get_only", verb);
      const auto serialized_get = get.build_request();
      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_get);
      frontend.process(rpc_ctx);
      const auto serialized_response = rpc_ctx->serialise_response();
      const auto response = parse_response(serialized_response);
      if (verb == HTTP_GET)
      {
        CHECK(response.status == HTTP_STATUS_OK);
      }
      else
      {
        CHECK(response.status == other_verb_status);
        const auto it = response.headers.find(http::headers::ALLOW);
        REQUIRE(it != response.headers.end());
        const auto v = it->second;
        CHECK(v.find(llhttp_method_name(HTTP_GET)) != std::string::npos);
      }
    }

    {
      http::Request post("post_only", verb);
      const auto serialized_post = post.build_request();
      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_post);
      frontend.process(rpc_ctx);
      const auto serialized_response = rpc_ctx->serialise_response();
      const auto response = parse_response(serialized_response);
      if (verb == HTTP_POST)
      {
        CHECK(response.status == HTTP_STATUS_OK);
      }
      else
      {
        CHECK(response.status == other_verb_status);
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
        ccf::make_rpc_context(user_session, serialized_put_or_delete);
      frontend.process(rpc_ctx);
      const auto serialized_response = rpc_ctx->serialise_response();
      const auto response = parse_response(serialized_response);
      if (verb == HTTP_PUT || verb == HTTP_DELETE)
      {
        CHECK(response.status == HTTP_STATUS_OK);
      }
      else
      {
        CHECK(response.status == other_verb_status);
        const auto it = response.headers.find(http::headers::ALLOW);
        REQUIRE(it != response.headers.end());
        const auto v = it->second;
        CHECK(v.find(llhttp_method_name(HTTP_PUT)) != std::string::npos);
        CHECK(v.find(llhttp_method_name(HTTP_DELETE)) != std::string::npos);
        if (verb != HTTP_OPTIONS)
        {
          CHECK(v.find(llhttp_method_name(verb)) == std::string::npos);
        }
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

      const nlohmann::json request_body = {
        {"value", new_value}, {"status", status}};
      const auto serialized_body = serdes::pack(request_body, default_pack);
      request.set_body(&serialized_body);

      const auto serialized_request = request.build_request();
      auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_request);
      frontend.process(rpc_ctx);
      const auto serialized_response = rpc_ctx->serialise_response();
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
        auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_request);
        frontend.process(rpc_ctx);
        const auto serialized_response = rpc_ctx->serialise_response();
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
    auto command = create_simple_request("/command");
    const auto serialized_command = command.build_request();

    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_command);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);
  }

  for (auto verb : {HTTP_GET, HTTP_POST})
  {
    http::Request read_only("read_only", verb);
    const auto serialized_read_only = read_only.build_request();

    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_read_only);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);
  }
}

TEST_CASE("Templated paths")
{
  NetworkState network;
  prepare_callers(network);
  TestTemplatedPaths frontend(*network.tables);

  {
    auto request = create_simple_request("/fin%3A/fang/foom");
    const auto serialized_request = request.build_request();

    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_request);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);

    std::map<std::string, std::string> expected_mapping;
    expected_mapping["foo"] = "fin%3A";
    expected_mapping["bar"] = "fang";
    expected_mapping["baz"] = "foom";

    const auto response_json = nlohmann::json::parse(response.body);
    const auto actual_mapping = response_json.get<decltype(expected_mapping)>();

    CHECK(expected_mapping == actual_mapping);
  }

  {
    auto request = create_simple_request("/users/1/address");
    const auto serialized_request = request.build_request();

    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_request);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
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

TEST_CASE("Decoded Templated paths")
{
  NetworkState network;
  prepare_callers(network);
  TestDecodedTemplatedPaths frontend(*network.tables);

  {
    auto request = create_simple_request("/fin%3A/fang%2F/foom");
    const auto serialized_request = request.build_request();

    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_request);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);

    std::map<std::string, std::string> expected_mapping;
    expected_mapping["foo"] = "fin:";
    expected_mapping["bar"] = "fang/";
    expected_mapping["baz"] = "foom";

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

  auto backup_consensus = std::make_shared<kv::test::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto signed_call = create_signed_request(user_caller);
  auto serialized_signed_call = signed_call.build_request();
  auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_signed_call);
  frontend.process(rpc_ctx);
  auto response = parse_response(rpc_ctx->serialise_response());
  CHECK(response.status == HTTP_STATUS_OK);
}

TEST_CASE("Forwarding" * doctest::test_suite("forwarding"))
{
  NetworkState network_primary;

  NetworkState network_backup;
  prepare_callers(network_backup);

  TestForwardingUserFrontEnd user_frontend_primary(*network_primary.tables);
  TestForwardingUserFrontEnd user_frontend_backup(*network_backup.tables);

  auto primary_consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto channel_stub = std::make_shared<ChannelStubProxy>();
  auto rpc_responder = std::weak_ptr<ccf::AbstractRPCResponder>();
  auto rpc_map = std::weak_ptr<ccf::RPCMap>();
  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    rpc_responder, channel_stub, rpc_map, ConsensusType::CFT);
  auto backup_consensus = std::make_shared<kv::test::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto simple_call = create_simple_request();
  auto serialized_call = simple_call.build_request();

  auto backup_ctx = ccf::make_rpc_context(backup_user_session, serialized_call);
  auto ctx = ccf::make_rpc_context(user_session, serialized_call);

  {
    INFO("Backup frontend without forwarder does not forward");
    REQUIRE(channel_stub->is_empty());

    user_frontend_backup.process(backup_ctx);
    REQUIRE(!backup_ctx->response_is_pending);
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(backup_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
  }

  user_frontend_backup.set_cmd_forwarder(backup_forwarder);
  backup_ctx->get_session_context()->is_forwarding = false;

  {
    INFO("Read command is not forwarded to primary");
    TestUserFrontend user_frontend_backup_read(*network_backup.tables);
    REQUIRE(channel_stub->is_empty());

    user_frontend_backup_read.process(backup_ctx);
    REQUIRE(!backup_ctx->response_is_pending);
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(backup_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);
  }

  {
    INFO("Write command on backup is forwarded to primary");
    REQUIRE(channel_stub->is_empty());

    user_frontend_backup.process(backup_ctx);
    REQUIRE(backup_ctx->response_is_pending);
    REQUIRE(channel_stub->size() == 1);

    auto forwarded_msg = channel_stub->get_pop_back();
    auto fwd_ctx =
      backup_forwarder->recv_forwarded_command<ccf::ForwardedHeader_v1>(
        kv::test::FirstBackupNodeId,
        forwarded_msg.data(),
        forwarded_msg.size());

    {
      INFO("Invalid caller");
      user_frontend_primary.process_forwarded(fwd_ctx);
      auto response = parse_response(fwd_ctx->serialise_response());
      CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
    };

    prepare_callers(network_primary);

    {
      INFO("Valid caller");
      user_frontend_primary.process_forwarded(fwd_ctx);
      auto response = parse_response(fwd_ctx->serialise_response());
      CHECK(response.status == HTTP_STATUS_OK);
    }
  }

  {
    INFO("Forwarding write command to a backup returns error");
    REQUIRE(channel_stub->is_empty());

    user_frontend_backup.process(backup_ctx);
    REQUIRE(backup_ctx->response_is_pending);
    REQUIRE(channel_stub->size() == 1);

    auto forwarded_msg = channel_stub->get_pop_back();
    auto fwd_ctx =
      backup_forwarder->recv_forwarded_command<ccf::ForwardedHeader_v1>(
        kv::test::FirstBackupNodeId,
        forwarded_msg.data(),
        forwarded_msg.size());

    // Processing forwarded response by a backup frontend (here, the same
    // frontend that the command was originally issued to)
    user_frontend_backup.process_forwarded(fwd_ctx);
    auto response = parse_response(fwd_ctx->serialise_response());

    // Command was already forwarded
    CHECK(response.status == HTTP_STATUS_SERVICE_UNAVAILABLE);
  }

  {
    // A write was executed on this frontend (above), so reads must be
    // forwarded too for session consistency
    INFO("Read command is now forwarded to primary on this session");

    TestUserFrontend user_frontend_backup_read(*network_backup.tables);
    user_frontend_backup_read.set_cmd_forwarder(backup_forwarder);
    REQUIRE(channel_stub->is_empty());

    user_frontend_backup_read.process(backup_ctx);
    REQUIRE(backup_ctx->response_is_pending);
    REQUIRE(channel_stub->size() == 1);

    channel_stub->clear();
  }

  {
    INFO("Client signature on forwarded RPC is recorded by primary");

    REQUIRE(channel_stub->is_empty());
    auto signed_call = create_signed_request(user_caller);
    auto serialized_signed_call = signed_call.build_request();
    auto signed_ctx =
      ccf::make_rpc_context(user_session, serialized_signed_call);
    user_frontend_backup.process(signed_ctx);
    REQUIRE(signed_ctx->response_is_pending);
    REQUIRE(channel_stub->size() == 1);

    auto forwarded_msg = channel_stub->get_pop_back();
    auto fwd_ctx =
      backup_forwarder->recv_forwarded_command<ccf::ForwardedHeader_v1>(
        kv::test::FirstBackupNodeId,
        forwarded_msg.data(),
        forwarded_msg.size());

    user_frontend_primary.process_forwarded(fwd_ctx);
    auto response = parse_response(fwd_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);
  }

  // On a session that was previously forwarded, and is now primary,
  // commands should still succeed
  ctx->get_session_context()->is_forwarding = true;
  {
    INFO("Write command primary on a forwarded session succeeds");
    REQUIRE(channel_stub->is_empty());

    user_frontend_primary.process(ctx);
    CHECK(!ctx->response_is_pending);
    auto response = parse_response(ctx->serialise_response());
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
  StubNodeContext context;

  TestForwardingNodeFrontEnd node_frontend_primary(network_primary, context);
  TestForwardingNodeFrontEnd node_frontend_backup(network_backup, context);

  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto primary_consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto rpc_responder = std::weak_ptr<ccf::AbstractRPCResponder>();
  auto rpc_map = std::weak_ptr<ccf::RPCMap>();
  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    rpc_responder, channel_stub, rpc_map, ConsensusType::CFT);
  node_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::test::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto node_session = std::make_shared<ccf::SessionContext>(
    ccf::InvalidSessionId, node_caller.raw());
  auto ctx = ccf::make_rpc_context(node_session, serialized_call);
  node_frontend_backup.process(ctx);
  REQUIRE(ctx->response_is_pending);
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto fwd_ctx =
    backup_forwarder->recv_forwarded_command<ccf::ForwardedHeader_v1>(
      kv::test::FirstBackupNodeId, forwarded_msg.data(), forwarded_msg.size());

  node_frontend_primary.process_forwarded(fwd_ctx);
  auto response = parse_response(fwd_ctx->serialise_response());
  CHECK(response.status == HTTP_STATUS_OK);

  CHECK(node_frontend_primary.last_caller_cert == node_caller);
  CHECK(!node_frontend_primary.last_caller_id.has_value());
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

  auto primary_consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto rpc_responder = std::weak_ptr<ccf::AbstractRPCResponder>();
  auto rpc_map = std::weak_ptr<ccf::RPCMap>();
  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    rpc_responder, channel_stub, rpc_map, ConsensusType::CFT);
  user_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::test::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto ctx = ccf::make_rpc_context(user_session, serialized_call);
  user_frontend_backup.process(ctx);
  REQUIRE(ctx->response_is_pending);
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto fwd_ctx =
    backup_forwarder->recv_forwarded_command<ccf::ForwardedHeader_v1>(
      kv::test::FirstBackupNodeId, forwarded_msg.data(), forwarded_msg.size());

  user_frontend_primary.process_forwarded(fwd_ctx);
  auto response = parse_response(fwd_ctx->serialise_response());
  CHECK(response.status == HTTP_STATUS_OK);

  CHECK(user_frontend_primary.last_caller_cert == user_caller);
  CHECK(user_frontend_primary.last_caller_id.value() == user_id.value());
}

TEST_CASE("Memberfrontend forwarding" * doctest::test_suite("forwarding"))
{
  NetworkState network_primary;
  prepare_callers(network_primary);

  NetworkState network_backup;
  prepare_callers(network_backup);

  ShareManager share_manager(network_primary);
  StubNodeContext context;

  TestForwardingMemberFrontEnd member_frontend_primary(
    network_primary, context, share_manager);
  TestForwardingMemberFrontEnd member_frontend_backup(
    network_backup, context, share_manager);
  auto channel_stub = std::make_shared<ChannelStubProxy>();

  auto primary_consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network_primary.tables->set_consensus(primary_consensus);

  auto rpc_responder = std::weak_ptr<ccf::AbstractRPCResponder>();
  auto rpc_map = std::weak_ptr<ccf::RPCMap>();
  auto backup_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
    rpc_responder, channel_stub, rpc_map, ConsensusType::CFT);
  member_frontend_backup.set_cmd_forwarder(backup_forwarder);
  auto backup_consensus = std::make_shared<kv::test::BackupStubConsensus>();
  network_backup.tables->set_consensus(backup_consensus);

  auto write_req = create_simple_request();
  auto serialized_call = write_req.build_request();

  auto ctx = ccf::make_rpc_context(member_session, serialized_call);
  member_frontend_backup.process(ctx);
  REQUIRE(ctx->response_is_pending);
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto fwd_ctx =
    backup_forwarder->recv_forwarded_command<ccf::ForwardedHeader_v1>(
      kv::test::FirstBackupNodeId, forwarded_msg.data(), forwarded_msg.size());

  member_frontend_primary.process_forwarded(fwd_ctx);
  auto response = parse_response(fwd_ctx->serialise_response());
  CHECK(response.status == HTTP_STATUS_OK);

  CHECK(member_frontend_primary.last_caller_cert == member_cert);
  CHECK(member_frontend_primary.last_caller_id.value() == member_id.value());
}

class TestConflictFrontend : public BaseTestFrontend
{
public:
  using Values = kv::Map<size_t, size_t>;

  TestConflictFrontend(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto conflict = [this](auto& ctx) {
      size_t retry_count =
        std::stoi(ctx.rpc_ctx->get_request_header("test-retry-count")
                    .value()); // This header only exists in the context of
                               // this test

      static size_t execution_count = 0;

      auto conflict_map = ctx.tx.template rw<Values>("test_values_conflict");
      conflict_map->get(0); // Record a read dependency

      if (execution_count++ < retry_count)
      {
        // Warning: Never do this in a real application!
        // Create another transaction that conflicts with the frontend one
        auto tx = this->tables.create_tx();
        auto conflict_map = tx.template rw<Values>("test_values_conflict");
        conflict_map->put(0, 42);
        REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

        // Indicate that the execution conflicted
        ctx.rpc_ctx->set_response_header("test-has-conflicted", "true");
      }
      else
      {
        // No response header if no conflict
        execution_count = 0;
      }

      ctx.rpc_ctx->set_response_header("test-execution-count", execution_count);

      conflict_map->put(0, 0);

      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/conflict", HTTP_POST, conflict).install();
  }
};

TEST_CASE("Retry on conflict")
{
  NetworkState network;
  prepare_callers(network);
  TestConflictFrontend frontend(*network.tables);

  auto req = create_simple_request("/conflict");

  constexpr size_t ccf_max_attempts = 30; // Defined by CCF (frontend.h)

  INFO("Does not reach execution limit");
  {
    size_t retry_count = ccf_max_attempts - 1;
    req.set_header("test-retry-count", fmt::format("{}", retry_count));
    auto serialized_call = req.build_request();
    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);

    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);

    // Response headers are cleared once conflict is resolved
    CHECK(
      response.headers.find("test-has-conflicted") == response.headers.end());
    CHECK(response.headers["test-execution-count"] == "0");
  }

  INFO("Reaches execution limit");
  {
    size_t retry_count = ccf_max_attempts + 1;
    req.set_header("test-retry-count", fmt::format("{}", retry_count));
    auto serialized_call = req.build_request();
    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);

    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_SERVICE_UNAVAILABLE);

    CHECK(response.headers["test-has-conflicted"] == "true");
    CHECK(
      response.headers["test-execution-count"] ==
      fmt::format("{}", ccf_max_attempts));
  }
}

class TestManualConflictsFrontend : public BaseTestFrontend
{
public:
  using MyVals = kv::Map<size_t, size_t>;
  static constexpr auto SRC = "source";
  static constexpr auto DST = "destination";

  static constexpr size_t KEY = 42;

  struct WaitPoint
  {
    std::mutex m;
    std::condition_variable cv;
    bool ready = false;

    void wait()
    {
      std::unique_lock lock(m);
      cv.wait(lock, [this] { return ready; });
    }

    void notify()
    {
      {
        std::lock_guard lock(m);
        ready = true;
      }
      cv.notify_one();
    }
  };

  WaitPoint before_read;
  WaitPoint after_read;
  WaitPoint before_write;
  WaitPoint after_write;

  TestManualConflictsFrontend(kv::Store& tables) : BaseTestFrontend(tables)
  {
    open();

    auto pausable = [this](auto& ctx) {
      auto src_handle = ctx.tx.template rw<MyVals>(SRC);
      auto dst_handle = ctx.tx.template rw<MyVals>(DST);

      before_read.wait();
      auto val = src_handle->get(KEY).value_or(0); // Record a read dependency
      after_read.notify();

      before_write.wait();
      dst_handle->put(KEY, val); // Create a write dependency
      after_write.notify();

      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    };
    make_endpoint("/pausable", HTTP_POST, pausable, {user_cert_auth_policy})
      .install();
  }
};

TEST_CASE("Manual conflicts")
{
  NetworkState network;
  prepare_callers(network);

  using TF = TestManualConflictsFrontend;
  TF frontend(*network.tables);

  auto call_pausable = [&](
                         std::shared_ptr<ccf::SessionContext> session,
                         http_status expected_status) {
    auto req = create_simple_request("/pausable");
    auto serialized_call = req.build_request();
    auto rpc_ctx = ccf::make_rpc_context(session, serialized_call);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == expected_status);
  };

  auto get_metrics = [&]() {
    auto req = create_simple_request("/api/metrics");
    req.set_method(HTTP_GET);
    auto serialized_call = req.build_request();
    auto rpc_ctx = ccf::make_rpc_context(user_session, serialized_call);
    frontend.process(rpc_ctx);
    auto response = parse_response(rpc_ctx->serialise_response());
    CHECK(response.status == HTTP_STATUS_OK);
    auto body = nlohmann::json::parse(response.body);
    auto& element = body["metrics"];
    ccf::EndpointMetricsEntry ret;
    for (const auto& j : element)
    {
      if (j["path"] == "pausable")
      {
        ret = j.get<ccf::EndpointMetricsEntry>();
        break;
      }
    }

    return ret;
  };

  auto get_value = [&](const std::string& table = TF::DST) {
    auto tx = network.tables->create_tx();
    auto handle = tx.ro<TF::MyVals>(table);
    auto ret = handle->get(TF::KEY);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    return ret;
  };

  auto update_value =
    [&](size_t n, const std::string& table = TF::SRC, size_t key = TF::KEY) {
      auto tx = network.tables->create_tx();
      using TF = TestManualConflictsFrontend;
      auto handle = tx.wo<TF::MyVals>(table);
      handle->put(key, n);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    };

  auto run_test = [&](
                    std::function<void()>&& read_write_op,
                    std::shared_ptr<ccf::SessionContext> session = user_session,
                    http_status expected_status = HTTP_STATUS_OK) {
    frontend.before_read.ready = false;
    frontend.after_read.ready = false;
    frontend.before_write.ready = false;
    frontend.after_write.ready = false;

    std::thread worker(call_pausable, session, expected_status);

    frontend.before_read.notify();
    frontend.after_read.wait();

    read_write_op();

    frontend.before_write.notify();
    frontend.after_write.wait();

    worker.join();
  };

  {
    INFO("No conflicts");

    const auto new_value = rand();
    update_value(new_value);

    const auto metrics_before = get_metrics();
    run_test([]() {});
    const auto metrics_after = get_metrics();

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == new_value);

    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries);
  }

  {
    INFO("Unauth'd access");

    call_pausable(invalid_session, HTTP_STATUS_UNAUTHORIZED);
  }

  {
    INFO("Inserted post-read conflict");

    const auto new_value = rand();
    const auto metrics_before = get_metrics();
    run_test([&]() { update_value(new_value); });
    const auto metrics_after = get_metrics();

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == new_value);

    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries + 1);
  }

  {
    INFO("Pure reads are not a conflict");

    const auto new_value = rand();
    update_value(new_value);
    const auto metrics_before = get_metrics();
    run_test([&]() {
      get_value(TF::SRC);
      get_value(TF::DST);
      get_value("Some other table");
    });
    const auto metrics_after = get_metrics();

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == new_value);

    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries);
  }

  {
    INFO("Unrelated writes are not a conflict");

    const auto new_value = rand();
    update_value(new_value);
    const auto metrics_before = get_metrics();
    run_test([&]() {
      update_value(rand(), TF::SRC, TF::KEY + 1);
      update_value(rand(), TF::DST);
      update_value(rand(), "Some other table");
    });
    const auto metrics_after = get_metrics();

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == new_value);

    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries);
  }

  {
    INFO("Inserted post-read delete");
    // Ensuring that a delete is not treated differently from a 'normal' write

    update_value(rand());
    const auto metrics_before = get_metrics();
    run_test([&]() {
      auto tx = network.tables->create_tx();
      using TF = TestManualConflictsFrontend;
      auto handle = tx.wo<TF::MyVals>(TF::SRC);
      handle->remove(TF::KEY);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    });
    const auto metrics_after = get_metrics();

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == 0);

    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries + 1);
  }

  {
    INFO("Inserted post-read clear");
    // Ensuring that a clear is not treated differently from a 'normal' write

    update_value(rand());
    const auto metrics_before = get_metrics();
    run_test([&]() {
      auto tx = network.tables->create_tx();
      using TF = TestManualConflictsFrontend;
      auto handle = tx.wo<TF::MyVals>(TF::SRC);
      handle->clear();
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    });
    const auto metrics_after = get_metrics();

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == 0);

    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries + 1);
  }

  {
    INFO("Removed caller ident post-read");

    const auto metrics_before = get_metrics();

    const auto old_value = get_value();
    update_value(rand());
    run_test(
      [&]() {
        auto tx = network.tables->create_tx();
        GenesisGenerator g(network, tx);
        g.remove_user(user_id);
        CHECK(tx.commit() == kv::CommitResult::SUCCESS);
      },
      user_session,
      HTTP_STATUS_UNAUTHORIZED);

    const auto v = get_value();
    REQUIRE(v.has_value());
    REQUIRE(v.value() == old_value);

    const auto metrics_after = get_metrics();
    REQUIRE(metrics_after.calls == metrics_before.calls + 1);
    REQUIRE(metrics_after.retries == metrics_before.retries + 1);
    REQUIRE(metrics_after.errors == metrics_before.errors + 1);
  }
}

int main(int argc, char** argv)
{
  ccf::enclavetime::last_value =
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch());

  threading::ThreadMessaging::init(1);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}