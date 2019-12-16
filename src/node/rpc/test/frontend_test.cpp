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

class TestUserFrontend : public ccf::UserRpcFrontend
{
public:
  TestUserFrontend(Store& tables) : UserRpcFrontend(tables)
  {
    auto empty_function = [this](RequestArgs& args) {
      return jsonrpc::success(true);
    };
    install("empty_function", empty_function, Read);
  }
};

class TestReqNotStoredFrontend : public ccf::UserRpcFrontend
{
public:
  TestReqNotStoredFrontend(Store& tables) : UserRpcFrontend(tables)
  {
    auto empty_function = [this](RequestArgs& args) {
      return jsonrpc::success(true);
    };
    install("empty_function", empty_function, Read);
    disable_request_storing();
  }
};

class TestMinimalHandleFunction : public ccf::UserRpcFrontend
{
public:
  TestMinimalHandleFunction(Store& tables) : UserRpcFrontend(tables)
  {
    auto echo_function = [this](Store::Tx& tx, const nlohmann::json& params) {
      return jsonrpc::success(params);
    };
    install("echo_function", echo_function, Read);
  }
};

class TestMemberFrontend : public ccf::MemberRpcFrontend
{
public:
  TestMemberFrontend(
    Store& tables, ccf::NetworkState& network, ccf::StubNodeState& node) :
    MemberRpcFrontend(network, node)
  {
    auto empty_function = [this](RequestArgs& args) {
      return jsonrpc::success(true);
    };
    install("empty_function", empty_function, Read);
  }
};

class TestNoCertsFrontend : public ccf::RpcFrontend<Users>
{
public:
  TestNoCertsFrontend(Store& tables) : RpcFrontend(tables)
  {
    auto empty_function = [this](RequestArgs& args) {
      return jsonrpc::success(true);
    };
    install("empty_function", empty_function, Read);
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
    last_caller_cert = std::vector<uint8_t>(args.rpc_ctx.session.caller_cert);
    last_caller_id = args.caller_id;
  }
};

class TestForwardingUserFrontEnd : public ccf::UserRpcFrontend,
                                   public RpcContextRecorder
{
public:
  TestForwardingUserFrontEnd(Store& tables) : UserRpcFrontend(tables)
  {
    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      return jsonrpc::success(true);
    };

    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    install("empty_function", empty_function, Write);
  }
};

class TestForwardingNodeFrontEnd : public ccf::NodeRpcFrontend,
                                   public RpcContextRecorder
{
public:
  TestForwardingNodeFrontEnd(
    ccf::NetworkState& network, ccf::StubNodeState& node) :
    NodeRpcFrontend(network, node)
  {
    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      return jsonrpc::success(true);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    install("empty_function", empty_function, Write);
  }
};

class TestForwardingMemberFrontEnd : public ccf::MemberRpcFrontend,
                                     public RpcContextRecorder
{
public:
  TestForwardingMemberFrontEnd(
    Store& tables, ccf::NetworkState& network, ccf::StubNodeState& node) :
    MemberRpcFrontend(network, node)
  {
    auto empty_function = [this](RequestArgs& args) {
      record_ctx(args);
      return jsonrpc::success(true);
    };
    // Note that this a Write function so that a backup executing this command
    // will forward it to the primary
    install("empty_function", empty_function, Write);
  }
};

class TestNoForwardingFrontEnd : public ccf::RpcFrontend<Users>
{
public:
  TestNoForwardingFrontEnd(Store& tables) : RpcFrontend(tables)
  {
    auto empty_function = [this](RequestArgs& args) {
      return jsonrpc::success(true);
    };
    // Note that this a Write function that cannot be forwarded
    install("empty_function", empty_function, Write, Forwardable::DoNotForward);
  }
};

namespace userapp
{
  enum class AppError : jsonrpc::ErrorBaseType
  {
    Foo = static_cast<jsonrpc::ErrorBaseType>(
      jsonrpc::CCFErrorCodes::APP_ERROR_START),
    Bar = Foo - 1
  };

  inline std::string get_error_prefix(AppError ec)
  {
    switch (ec)
    {
      case (AppError::Foo):
      {
        return "FOO: ";
      }
      case (AppError::Bar):
      {
        return "BAR: ";
      }
    }

    throw std::logic_error("Missing case");
  }
}

class TestAppErrorFrontEnd : public ccf::RpcFrontend<Users>
{
public:
  static constexpr auto bar_msg = "Bar is broken";

  TestAppErrorFrontEnd(Store& tables) : RpcFrontend(tables)
  {
    auto foo = [this](RequestArgs& args) {
      return jsonrpc::error(userapp::AppError::Foo);
    };
    install("foo", foo, Read);

    auto bar = [this](RequestArgs& args) {
      return jsonrpc::error(userapp::AppError::Bar, bar_msg);
    };
    install("bar", bar, Read);
  }
};

// used throughout
auto kp = tls::make_key_pair();
ccf::NetworkState network;
ccf::NetworkState network2;
auto encryptor = std::make_shared<ccf::NullTxEncryptor>();

#ifdef PBFT
ccf::NetworkState pbft_network(ConsensusType::Pbft);
auto history_kp = tls::make_key_pair();

auto history = std::make_shared<ccf::NullTxHistory>(
  *pbft_network.tables,
  0,
  *history_kp,
  pbft_network.signatures,
  pbft_network.nodes);

#endif

ccf::StubNodeState stub_node;

std::vector<uint8_t> sign_json(nlohmann::json j)
{
  auto contents = nlohmann::json::to_msgpack(j);
  return kp->sign(contents);
}

auto create_simple_json()
{
  nlohmann::json j;
  j[jsonrpc::JSON_RPC] = jsonrpc::RPC_VERSION;
  j[jsonrpc::ID] = 1;
  j[jsonrpc::METHOD] = "empty_function";
  j[jsonrpc::PARAMS] = nlohmann::json::object();
  return j;
}

auto create_signed_json(const nlohmann::json& j = create_simple_json())
{
  nlohmann::json sj;
  sj["req"] = j;
  auto sig = sign_json(j);
  sj["sig"] = sig;
  return sj;
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

static constexpr auto default_pack = jsonrpc::Pack::MsgPack;

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
  member_id = g.add_member(member_caller);
  invalid_member_id = g.add_member(invalid_caller);
  CHECK(g.finalize() == kv::CommitSuccess::OK);
}

void add_callers_primary_store()
{
  Store::Tx gen_tx;
  network2.tables->clear();
  GenesisGenerator g(network2, gen_tx);
  g.init_values();
  user_id = g.add_user(user_caller);
  member_id = g.add_member(member_caller);
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
  auto simple_call = create_simple_json();
  const auto serialized_call = jsonrpc::pack(simple_call, default_pack);
  auto actor = ActorsType::users;
  pbft::Request request = {actor, user_id, user_caller_der, serialized_call};

  const enclave::SessionContext session(
    enclave::InvalidSessionId, user_id, user_caller_der);
  auto ctx = enclave::make_rpc_context(session, request.raw);
  ctx.actor = (ccf::ActorsType)request.actor;
  frontend.process_pbft(ctx);

  Store::Tx tx;
  auto pbft_metadata = tx.get_view(pbft_network.pbft_requests);
  auto request_value = pbft_metadata->get(0);
  REQUIRE(request_value.has_value());

  auto deserialised_request = request_value.value();
  REQUIRE(deserialised_request.actor == actor);
  REQUIRE(deserialised_request.caller_id == user_id);
  REQUIRE(deserialised_request.caller_cert == user_caller_der);
  auto deserialised_simple_call =
    jsonrpc::unpack(deserialised_request.raw, default_pack);
  REQUIRE(
    deserialised_simple_call[jsonrpc::METHOD] == simple_call[jsonrpc::METHOD]);
}
#else

TEST_CASE("SignedReq to and from json")
{
  ccf::SignedReq sr;
  REQUIRE(sr.sig.empty());
  REQUIRE(sr.req.empty());

  nlohmann::json j = sr;

  sr = j;
  REQUIRE(sr.sig.empty());
  REQUIRE(sr.req.empty());
}

TEST_CASE("process_json")
{
  prepare_callers();
  TestUserFrontend frontend(*network.tables);
  auto simple_call = create_simple_json();

  const auto serialized_call = jsonrpc::pack(simple_call, default_pack);
  const auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);

  Store::Tx tx;
  CallerId caller_id(0);
  auto response = frontend.process_json(rpc_ctx, tx, caller_id).value();
  CHECK(response[jsonrpc::RESULT] == true);
}

TEST_CASE("process")
{
  prepare_callers();
  TestUserFrontend frontend(*network.tables);
  const auto simple_call = create_simple_json();
  const auto signed_call = create_signed_json();

  SUBCASE("without signature")
  {
    const auto serialized_call = jsonrpc::pack(simple_call, default_pack);
    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend.process(rpc_ctx).value();
    auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(response[jsonrpc::RESULT] == true);

    auto signed_resp = get_signed_req(user_id);
    CHECK(!signed_resp.has_value());
  }

  SUBCASE("with signature")
  {
    const auto serialized_call = jsonrpc::pack(signed_call, default_pack);
    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend.process(rpc_ctx).value();
    auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(response[jsonrpc::RESULT] == true);

    auto signed_resp = get_signed_req(user_id);
    CHECK(signed_resp.has_value());
    auto value = signed_resp.value();
    ccf::SignedReq signed_req(signed_call);
    CHECK(value.req == signed_req.req);
    CHECK(value.sig == signed_req.sig);
  }

  SUBCASE("request with signature but do not store")
  {
    TestReqNotStoredFrontend frontend_nostore(*network.tables);
    const auto serialized_call = jsonrpc::pack(signed_call, default_pack);
    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_call);

    const auto serialized_response = frontend_nostore.process(rpc_ctx).value();
    const auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(response[jsonrpc::RESULT] == true);

    auto signed_resp = get_signed_req(user_id);
    CHECK(signed_resp.has_value());
    auto value = signed_resp.value();
    CHECK(value.req.empty());
    CHECK(value.sig == signed_call[jsonrpc::SIG]);
  }
  // TODO: verify_client_signature
#  ifndef HTTP
  SUBCASE("signature not verified")
  {
    const auto serialized_call = jsonrpc::pack(signed_call, default_pack);
    const auto invalid_rpc_ctx =
      enclave::make_rpc_context(invalid_session, serialized_call);

    const auto serialized_response = frontend.process(invalid_rpc_ctx).value();
    const auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::INVALID_CLIENT_SIGNATURE));

    const auto signed_resp = get_signed_req(invalid_user_id);
    CHECK(!signed_resp.has_value());
  }
#  endif
}

TEST_CASE("MinimalHandleFuction")
{
  prepare_callers();
  TestMinimalHandleFunction frontend(*network.tables);
  auto echo_call = create_simple_json();
  echo_call[jsonrpc::METHOD] = "echo_function";
  echo_call[jsonrpc::PARAMS] = {{"data", {"nested", "Some string"}},
                                {"other", "Another string"}};

  const auto signed_call = create_signed_json(echo_call);
  const auto serialized_call = jsonrpc::pack(signed_call, default_pack);

  const auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
  auto response =
    jsonrpc::unpack(frontend.process(rpc_ctx).value(), default_pack);
  CHECK(response[jsonrpc::RESULT] == echo_call[jsonrpc::PARAMS]);
}

// callers

TEST_CASE("User caller")
{
  prepare_callers();
  auto simple_call = create_simple_json();
  std::vector<uint8_t> serialized_call =
    jsonrpc::pack(simple_call, default_pack);
  TestUserFrontend frontend(*network.tables);

  SUBCASE("valid caller")
  {
    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(response[jsonrpc::RESULT] == true);
  }

  SUBCASE("invalid caller")
  {
    const auto member_rpc_ctx =
      enclave::make_rpc_context(member_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(member_rpc_ctx).value();
    auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::INVALID_CALLER_ID));
  }
}

TEST_CASE("Member caller")
{
  prepare_callers();
  auto simple_call = create_simple_json();
  std::vector<uint8_t> serialized_call =
    jsonrpc::pack(simple_call, default_pack);
  TestMemberFrontend frontend(*network.tables, network, stub_node);

  SUBCASE("valid caller")
  {
    const auto member_rpc_ctx =
      enclave::make_rpc_context(member_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(member_rpc_ctx).value();
    auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(response[jsonrpc::RESULT] == true);
  }

  SUBCASE("invalid caller")
  {
    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_call);
    std::vector<uint8_t> serialized_response =
      frontend.process(rpc_ctx).value();
    auto response = jsonrpc::unpack(serialized_response, default_pack);
    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::INVALID_CALLER_ID));
  }
}

TEST_CASE("No certs table")
{
  prepare_callers();

  auto simple_call = create_simple_json();
  std::vector<uint8_t> serialized_call =
    jsonrpc::pack(simple_call, default_pack);
  TestNoCertsFrontend frontend(*network.tables);

  const auto rpc_ctx = enclave::make_rpc_context(user_session, serialized_call);
  std::vector<uint8_t> serialized_response = frontend.process(rpc_ctx).value();
  auto response = jsonrpc::unpack(serialized_response, default_pack);
  CHECK(response[jsonrpc::RESULT] == true);
}

TEST_CASE("Signed read requests can be executed on backup")
{
  prepare_callers();

  TestUserFrontend frontend(*network.tables);

  auto backup_consensus = std::make_shared<kv::BackupStubConsensus>();
  network.tables->set_consensus(backup_consensus);

  auto signed_call = create_signed_json();
  auto serialized_signed_call = jsonrpc::pack(signed_call, default_pack);
  const auto rpc_ctx =
    enclave::make_rpc_context(user_session, serialized_signed_call);
  auto response =
    jsonrpc::unpack(frontend.process(rpc_ctx).value(), default_pack);

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

  auto write_req = create_simple_json();
  auto serialized_call = jsonrpc::pack(write_req, default_pack);

  const auto ctx = enclave::make_rpc_context(user_session, serialized_call);

  {
    INFO("Backup frontend without forwarder does not forward");
    REQUIRE(channel_stub->is_empty());

    const auto r = user_frontend_backup.process(ctx);
    REQUIRE(r.has_value());
    REQUIRE(channel_stub->is_empty());

    const auto response = jsonrpc::unpack(r.value(), default_pack);
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

    const auto response = jsonrpc::unpack(r.value(), default_pack);
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
      auto response = jsonrpc::unpack(
        user_frontend_primary.process_forwarded(fwd_ctx), default_pack);
      CHECK(
        response[jsonrpc::ERR][jsonrpc::CODE] ==
        static_cast<jsonrpc::ErrorBaseType>(
          jsonrpc::CCFErrorCodes::INVALID_CALLER_ID));
    };

    {
      INFO("Valid caller");
      add_callers_primary_store();
      auto response = jsonrpc::unpack(
        user_frontend_primary.process_forwarded(fwd_ctx), default_pack);
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
    auto response = jsonrpc::unpack(
      user_frontend_backup.process_forwarded(fwd_ctx), default_pack);

    CHECK(
      response[jsonrpc::ERR][jsonrpc::CODE] ==
      static_cast<jsonrpc::ErrorBaseType>(
        jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY));
  }

  {
    INFO("Client signature on forwarded RPC is recorded by primary");

    REQUIRE(channel_stub->is_empty());
    auto signed_call = create_signed_json();
    auto serialized_signed_call = jsonrpc::pack(signed_call, default_pack);
    const auto signed_ctx =
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
    REQUIRE(SignedReq(client_sig.value()) == SignedReq(signed_call));
  }

  {
    INFO("Write command should not be forwarded if marked as non-forwardable");
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

  auto write_req = create_simple_json();
  auto serialized_call = jsonrpc::pack(write_req, default_pack);

  const enclave::SessionContext node_session(
    enclave::InvalidSessionId, node_caller);
  const auto ctx = enclave::make_rpc_context(node_session, serialized_call);
  const auto r = node_frontend_backup.process(ctx);
  REQUIRE(!r.has_value());
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto [fwd_ctx, node_id] =
    backup_forwarder
      ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
      .value();

  auto response = jsonrpc::unpack(
    node_frontend_primary.process_forwarded(fwd_ctx), default_pack);

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

  auto write_req = create_simple_json();
  auto serialized_call = jsonrpc::pack(write_req, default_pack);

  const auto ctx = enclave::make_rpc_context(user_session, serialized_call);
  const auto r = user_frontend_backup.process(ctx);
  REQUIRE(!r.has_value());
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto [fwd_ctx, node_id] =
    backup_forwarder
      ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
      .value();

  auto response = jsonrpc::unpack(
    user_frontend_primary.process_forwarded(fwd_ctx), default_pack);

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

  auto write_req = create_simple_json();
  auto serialized_call = jsonrpc::pack(write_req, default_pack);

  const auto ctx = enclave::make_rpc_context(member_session, serialized_call);
  const auto r = member_frontend_backup.process(ctx);
  REQUIRE(!r.has_value());
  REQUIRE(channel_stub->size() == 1);

  auto forwarded_msg = channel_stub->get_pop_back();
  auto [fwd_ctx, node_id] =
    backup_forwarder
      ->recv_forwarded_command(forwarded_msg.data(), forwarded_msg.size())
      .value();

  auto response = jsonrpc::unpack(
    member_frontend_primary.process_forwarded(fwd_ctx), default_pack);

  CHECK(member_frontend_primary.last_caller_cert == member_caller_der);
  CHECK(member_frontend_primary.last_caller_id == 0);
}

TEST_CASE("App-defined errors")
{
  prepare_callers();

  TestAppErrorFrontEnd frontend(*network.tables);
  {
    auto foo_call = create_simple_json();
    foo_call[jsonrpc::METHOD] = "foo";
    std::vector<uint8_t> serialized_foo = jsonrpc::pack(foo_call, default_pack);

    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_foo);
    std::vector<uint8_t> serialized_foo_response =
      frontend.process(rpc_ctx).value();
    auto foo_response = jsonrpc::unpack(serialized_foo_response, default_pack);

    CHECK(foo_response[jsonrpc::ERR] != nullptr);
    CHECK(
      foo_response[jsonrpc::ERR][jsonrpc::CODE].get<jsonrpc::ErrorBaseType>() ==
      static_cast<jsonrpc::ErrorBaseType>(userapp::AppError::Foo));

    const auto msg =
      foo_response[jsonrpc::ERR][jsonrpc::MESSAGE].get<std::string>();
    CHECK(msg.find("FOO") != std::string::npos);
  }

  {
    auto bar_call = create_simple_json();
    bar_call[jsonrpc::METHOD] = "bar";
    std::vector<uint8_t> serialized_bar = jsonrpc::pack(bar_call, default_pack);

    const auto rpc_ctx =
      enclave::make_rpc_context(user_session, serialized_bar);
    std::vector<uint8_t> serialized_bar_response =
      frontend.process(rpc_ctx).value();
    auto bar_response = jsonrpc::unpack(serialized_bar_response, default_pack);

    CHECK(bar_response[jsonrpc::ERR] != nullptr);
    CHECK(
      bar_response[jsonrpc::ERR][jsonrpc::CODE].get<jsonrpc::ErrorBaseType>() ==
      static_cast<jsonrpc::ErrorBaseType>(userapp::AppError::Bar));

    const auto msg =
      bar_response[jsonrpc::ERR][jsonrpc::MESSAGE].get<std::string>();
    CHECK(msg.find("BAR") != std::string::npos);
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
