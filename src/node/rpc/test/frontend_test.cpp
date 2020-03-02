// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/appinterface.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/entities.h"
#include "node/genesisgen.h"
#include "node/networkstate.h"
#include "node/rpc/handleradapter.h"
#include "node/rpc/jsonrpc.h"
#include "node/rpc/memberfrontend.h"
#include "node/rpc/nodefrontend.h"
#include "node/rpc/userfrontend.h"
#include "node/test/channel_stub.h"
#include "node_stub.h"

#ifdef PBFT
#  include "consensus/pbft/pbftrequests.h"
#  include "node/history.h"
#endif
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
      args.rpc_ctx->set_response_result(true);
    };
    install("empty_function", empty_function, HandlerRegistry::Read);
  }
};

class TestReqNotStoredFrontend : public SimpleUserRpcFrontend
{
public:
  TestReqNotStoredFrontend(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_result(true);
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

    auto echo_function = [this](Store::Tx& tx, const nlohmann::json& params) {
      auto j = params;
      return make_success(std::move(j));
    };
    install("echo", handler_adapter(echo_function), HandlerRegistry::Read);

    auto get_caller_function =
      [this](Store::Tx& tx, CallerId caller_id, const nlohmann::json& params) {
        return make_success(caller_id);
      };
    install(
      "get_caller",
      handler_adapter(get_caller_function),
      HandlerRegistry::Read);

    auto failable_function =
      [this](Store::Tx& tx, CallerId caller_id, const nlohmann::json& params) {
        const auto it = params.find("error");
        if (it != params.end())
        {
          const size_t error_code = (*it)["code"];
          const std::string error_msg = (*it)["message"];

          return make_error(error_code, error_msg);
        }

        return make_success(true);
      };
    install(
      "failable", handler_adapter(failable_function), HandlerRegistry::Read);
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
      args.rpc_ctx->set_response_result(true);
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
      args.rpc_ctx->set_response_result(true);
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
    last_caller_cert = std::vector<uint8_t>(args.rpc_ctx->session.caller_cert);
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
      args.rpc_ctx->set_response_result(true);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    install("empty_function", empty_function, HandlerRegistry::Write);
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
      args.rpc_ctx->set_response_result(true);
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
      args.rpc_ctx->set_response_result(true);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    handlers.install("empty_function", empty_function, HandlerRegistry::Write);
  }
};

class TestNoForwardingFrontEnd : public SimpleUserRpcFrontend,
                                 public RpcContextRecorder
{
public:
  TestNoForwardingFrontEnd(Store& tables) : SimpleUserRpcFrontend(tables)
  {
    open();

    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      args.rpc_ctx->set_response_result(true);
    };
    // Note that this is a Write function that cannot be forwarded
    install(
      "empty_function",
      empty_function,
      HandlerRegistry::Write,
      HandlerRegistry::Forwardable::DoNotForward);
  }
};

namespace userapp
{
  enum AppError : jsonrpc::ErrorBaseType
  {
    Foo = static_cast<jsonrpc::ErrorBaseType>(
      jsonrpc::CCFErrorCodes::APP_ERROR_START),
    Bar = Foo - 1
  };
}

class TestAppErrorFrontEnd : public RpcFrontend
{
  HandlerRegistry handlers;

public:
  static constexpr auto bar_msg = "Bar is broken";

  TestAppErrorFrontEnd(Store& tables) :
    RpcFrontend(tables, handlers),
    handlers(tables)
  {
    auto foo = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_error(userapp::AppError::Foo);
    };
    handlers.install("foo", foo, HandlerRegistry::Read);

    auto bar = [this](RequestArgs& args) {
      args.rpc_ctx->set_response_error(userapp::AppError::Bar, bar_msg);
    };
    handlers.install("bar", bar, HandlerRegistry::Read);
  }
};

// used throughout
auto kp = tls::make_key_pair();
NetworkState network;
NetworkState network2;
auto encryptor = std::make_shared<NullTxEncryptor>();

#ifdef PBFT
NetworkState pbft_network(ConsensusType::Pbft);
auto history_kp = tls::make_key_pair();

auto history = std::make_shared<NullTxHistory>(
  *pbft_network.tables,
  0,
  *history_kp,
  pbft_network.signatures,
  pbft_network.nodes);

#endif

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
    http::headers::CONTENT_TYPE,
    pack == jsonrpc::Pack::Text ? http::headervalues::contenttype::JSON :
                                  (pack == jsonrpc::Pack::MsgPack ?
                                     http::headervalues::contenttype::MSGPACK :
                                     "unknown"));
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

nlohmann::json parse_response(
  const vector<uint8_t>& v, jsonrpc::Pack pack = default_pack)
{
  http::SimpleMsgProcessor processor;
  http::Parser parser(HTTP_RESPONSE, processor);

  const auto parsed_count = parser.execute(v.data(), v.size());
  REQUIRE(parsed_count == v.size());
  REQUIRE(processor.received.size() == 1);

  return jsonrpc::unpack(processor.received.front().body, pack);
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

std::vector<uint8_t> dummy_key_share = {1, 2, 3};

const enclave::SessionContext user_session(
  enclave::InvalidSessionId, user_caller_der);
const enclave::SessionContext invalid_session(
  enclave::InvalidSessionId, invalid_caller_der);
const enclave::SessionContext member_session(
  enclave::InvalidSessionId, member_caller_der);

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
  invalid_user_id = g.add_user(invalid_caller);
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

#ifdef PBFT

void add_callers_pbft_store()
{
  Store::Tx gen_tx;
  pbft_network.tables->set_encryptor(encryptor);
  pbft_network.tables->clear();
  pbft_network.tables->set_history(history);

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

  const enclave::SessionContext session(
    enclave::InvalidSessionId, user_id, user_caller_der);
  auto ctx = enclave::make_rpc_context(session, request.raw);
  frontend.process_pbft(ctx, true);

  Store::Tx tx;
  auto pbft_requests_map = tx.get_view(pbft_network.pbft_requests_map);
  auto request_value = pbft_requests_map->get(0);
  REQUIRE(request_value.has_value());

  pbft::Request deserialised_req = request_value.value();

  REQUIRE(deserialised_req.caller_id == user_id);
  REQUIRE(deserialised_req.caller_cert == user_caller_der);
  REQUIRE(deserialised_req.raw == serialized_call);
}
#else

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

TEST_CASE("process_command")
{
  prepare_callers();
  TestUserFrontend frontend(*network.tables);
  auto simple_call = create_simple_request();

  const auto serialized_call = simple_call.build_request();
  auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

  Store::Tx tx;
  CallerId caller_id(0);
  auto response = frontend.process_command(rpc_ctx, tx, caller_id);
  REQUIRE(response.has_value());

  auto j_result = parse_response(response.value());
  CHECK(j_result[jsonrpc::RESULT] == true);
}

TEST_CASE("process")
{
  prepare_callers();
  TestUserFrontend frontend(*network.tables);
  const auto simple_call = create_simple_request();
  const auto [signed_call, signed_req] = create_signed_request(simple_call);

  SUBCASE("invalid method")
  {
    constexpr auto method_name = "this_method_doesnt_exist";
    const auto invalid_call = create_simple_request(method_name);
    const auto serialized_call = invalid_call.build_request();
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    const auto err_it = response.find(jsonrpc::ERR);
    REQUIRE(err_it != response.end());
    const auto error_message =
      err_it->find(jsonrpc::MESSAGE)->get<std::string>();
    CHECK(error_message.find(method_name) != std::string::npos);
  }

  SUBCASE("without signature")
  {
    const auto serialized_call = simple_call.build_request();
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response[jsonrpc::RESULT] == true);

    auto signed_resp = get_signed_req(user_id);
    CHECK(!signed_resp.has_value());
  }

  SUBCASE("with signature")
  {
    const auto serialized_call = signed_call.build_request();
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response[jsonrpc::RESULT] == true);

    auto signed_resp = get_signed_req(user_id);
    REQUIRE(signed_resp.has_value());
    auto value = signed_resp.value();
    CHECK(value == signed_req);
  }

  SUBCASE("request with signature but do not store")
  {
    TestReqNotStoredFrontend frontend_nostore(*network.tables);
    const auto serialized_call = signed_call.build_request();
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend_nostore.process(rpc_ctx).value();
    const auto response = parse_response(serialized_response);
    CHECK(response[jsonrpc::RESULT] == true);

    auto signed_resp = get_signed_req(user_id);
    REQUIRE(signed_resp.has_value());
    auto value = signed_resp.value();
    CHECK(value.req.empty());
    CHECK(value.sig == signed_req.sig);
  }
}

TEST_CASE("MinimalHandleFunction")
{
  prepare_callers();
  TestMinimalHandleFunction frontend(*network.tables);
  for (const auto pack_type : {jsonrpc::Pack::Text, jsonrpc::Pack::MsgPack})
  {
    {
      auto echo_call = create_simple_request("echo", pack_type);
      const nlohmann::json j_body = {{"data", {"nested", "Some string"}},
                                     {"other", "Another string"}};
      const auto serialized_body = jsonrpc::pack(j_body, pack_type);

      auto [signed_call, signed_req] =
        create_signed_request(echo_call, &serialized_body);
      const auto serialized_call = signed_call.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response =
        parse_response(frontend.process(rpc_ctx).value(), pack_type);
      CHECK(response[jsonrpc::RESULT] == j_body);
    }

    {
      auto get_caller = create_simple_request("get_caller", pack_type);

      const auto [signed_call, signed_req] = create_signed_request(get_caller);
      const auto serialized_call = signed_call.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response =
        parse_response(frontend.process(rpc_ctx).value(), pack_type);
      CHECK(response[jsonrpc::RESULT] == user_id);
    }
  }

  {
    auto dont_fail = create_simple_request("failable");

    const auto [signed_call, signed_req] = create_signed_request(dont_fail);
    const auto serialized_call = signed_call.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
    auto response =
      parse_response(frontend.process(rpc_ctx).value(), default_pack);
    CHECK(response[jsonrpc::RESULT] == true);
  }

  {
    for (const size_t err :
         {(size_t)jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
          (size_t)jsonrpc::CCFErrorCodes::SCRIPT_ERROR,
          (size_t)42u})
    {
      const auto msg = fmt::format("An error message about {}", err);
      auto fail = create_simple_request("failable");
      const nlohmann::json j_body = {
        {"error", {{"code", err}, {"message", msg}}}};
      const auto serialized_body = jsonrpc::pack(j_body, default_pack);

      const auto [signed_call, signed_req] =
        create_signed_request(fail, &serialized_body);
      const auto serialized_call = signed_call.build_request();

      auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
      auto response =
        parse_response(frontend.process(rpc_ctx).value(), default_pack);

      const auto err_it = response.find(jsonrpc::ERR);
      REQUIRE(err_it != response.end());
      const auto error = *err_it;
      CHECK(error[jsonrpc::CODE] == err);
      const auto error_msg = error[jsonrpc::MESSAGE].get<std::string>();
      CHECK(error_msg.find(msg) != std::string::npos);
    }
  }
}

// callers

TEST_CASE("User caller")
{
  prepare_callers();
  auto simple_call = create_simple_request();
  std::vector<uint8_t> serialized_call = simple_call.build_request();
  TestUserFrontend frontend(*network.tables);

  SUBCASE("valid caller")
  {
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(response[jsonrpc::RESULT] == true);
  }

  SUBCASE("invalid caller")
  {
    auto member_rpc_ctx =
      enclave::make_rpc_context(member_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(member_rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::INVALID_CALLER_ID));
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
    CHECK(response[jsonrpc::RESULT] == true);
  }

  SUBCASE("invalid caller")
  {
    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = parse_response(serialized_response);
    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::INVALID_CALLER_ID));
  }
}

TEST_CASE("No certs table")
{
  prepare_callers();

  auto simple_call = create_simple_request();
  std::vector<uint8_t> serialized_call = simple_call.build_request();
  TestNoCertsFrontend frontend(*network.tables);

  auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
  std::vector<uint8_t> serialized_response = frontend.process(rpc_ctx).value();
  auto response = parse_response(serialized_response);
  CHECK(response[jsonrpc::RESULT] == true);
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

  CHECK(response[jsonrpc::RESULT] == true);
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

  auto ctx = enclave::make_rpc_context(user_session, serialized_call);

  {
    INFO("Backup frontend without forwarder does not forward");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(r.value());
    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY));
  }

  user_frontend_backup.set_cmd_forwarder(backup_forwarder);

  {
    INFO("Read command is not forwarded to primary");
    TestUserFrontend user_frontend_backup_read(*network.tables);
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup_read.process(ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->is_empty());

    const auto response = parse_response(r.value());
    CHECK(response[jsonrpc::RESULT] == true);
  }

  {
    INFO("Write command on backup is forwarded to primary");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(ctx);
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
      CHECK(
        response[jsonrpc::ERR][jsonrpc::CODE] ==
        static_cast<jsonrpc::ErrorBaseType>(
          jsonrpc::CCFErrorCodes::INVALID_CALLER_ID));
    };

    {
      INFO("Valid caller");
      add_callers_primary_store();
      auto response =
        parse_response(user_frontend_primary.process_forwarded(fwd_ctx));
      CHECK(response[jsonrpc::RESULT] == true);
    }
  }

  {
    INFO("Forwarding write command to a backup return TX_NOT_PRIMARY");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(ctx);
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

    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY));
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

  {
    INFO(
      "HandlerRegistry::Write command should not be forwarded if marked as "
      "non-forwardable");
    TestNoForwardingFrontEnd user_frontend_backup_no_forwarding(
      *network.tables);

    auto backup2_forwarder = std::make_shared<Forwarder<ChannelStubProxy>>(
      nullptr, channel_stub, nullptr);
    auto backup2_consensus = std::make_shared<kv::BackupStubConsensus>();
    network.tables->set_consensus(backup_consensus);
    user_frontend_backup_no_forwarding.set_cmd_forwarder(backup2_forwarder);

    REQUIRE(channel_stub->is_empty());
    const auto r = user_frontend_backup_no_forwarding.process(ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->size() == 0);
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

  const enclave::SessionContext node_session(
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

  CHECK(member_frontend_primary.last_caller_cert == member_caller_der);
  CHECK(member_frontend_primary.last_caller_id == 0);
}

TEST_CASE("App-defined errors")
{
  prepare_callers();

  TestAppErrorFrontEnd frontend(*network.tables);
  {
    auto foo_call = create_simple_request("foo");
    auto serialized_foo = foo_call.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_foo);
    std::vector<uint8_t> serialized_foo_response =
      frontend.process(rpc_ctx).value();
    auto foo_response = parse_response(serialized_foo_response);

    CHECK(foo_response[jsonrpc::ERR] != nullptr);
    CHECK(
      foo_response[jsonrpc::ERR][jsonrpc::CODE].get<userapp::AppError>() ==
      userapp::AppError::Foo);

    const auto msg =
      foo_response[jsonrpc::ERR][jsonrpc::MESSAGE].get<std::string>();
  }

  {
    auto bar_call = create_simple_request("bar");
    auto serialized_bar = bar_call.build_request();

    auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_bar);
    std::vector<uint8_t> serialized_bar_response =
      frontend.process(rpc_ctx).value();
    auto bar_response = parse_response(serialized_bar_response);

    CHECK(bar_response[jsonrpc::ERR] != nullptr);
    CHECK(
      bar_response[jsonrpc::ERR][jsonrpc::CODE].get<userapp::AppError>() ==
      userapp::AppError::Bar);

    const auto msg =
      bar_response[jsonrpc::ERR][jsonrpc::MESSAGE].get<std::string>();
    CHECK(msg.find(TestAppErrorFrontEnd::bar_msg) != std::string::npos);
  }
}

#endif

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
