// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/serdes.h"
#include "frontend_test_infra.h"
#include "kv/test/null_encryptor.h"
#include "nlohmann/json.hpp"
#include "node/rpc/node_frontend.h"
#include "node_stub.h"
#include "service/genesis_gen.h"

using namespace ccf;
using namespace nlohmann;
using namespace serdes;

using TResponse = http::SimpleResponseProcessor::Response;

auto node_id = 0;
threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;

TResponse frontend_process(
  NodeRpcFrontend& frontend,
  const json& json_params,
  const std::string& method,
  const crypto::Pem& caller)
{
  http::Request r(method);
  const auto body = json_params.is_null() ?
    std::vector<uint8_t>() :
    serdes::pack(json_params, Pack::Text);
  r.set_body(&body);
  auto serialise_request = r.build_request();

  auto session =
    std::make_shared<ccf::SessionContext>(ccf::InvalidSessionId, caller.raw());
  std::shared_ptr<RpcContextImpl> rpc_ctx =
    ccf::make_rpc_context(session, serialise_request);
  bool done_cb_called = false;
  frontend.process(rpc_ctx, [&](auto&& done_ctx) {
    rpc_ctx = std::move(done_ctx);
    done_cb_called = true;
  });

  threading::ThreadMessaging::thread_messaging.run_one();
  REQUIRE(done_cb_called);

  CHECK(!rpc_ctx->response_is_pending);
  const auto serialised_response = rpc_ctx->serialise_response();

  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  parser.execute(serialised_response.data(), serialised_response.size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

void require_ledger_secrets_equal(
  const LedgerSecretsMap& first, const LedgerSecretsMap& second)
{
  REQUIRE(first.size() == second.size());
  REQUIRE(std::equal(
    first.begin(),
    first.end(),
    second.begin(),
    [](const auto& a, const auto& b) { return (*a.second == *b.second); }));
}

TEST_CASE("Add a node to an opening service")
{
  NetworkState network;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_configuration({0, ConsensusType::CFT, std::nullopt});

  ShareManager share_manager(network);
  StubNodeContext context;
  NodeRpcFrontend frontend(network, context);
  frontend.open();

  network.identity = make_test_network_ident();
  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  network.ledger_secrets->init();

  // New node should not be given ledger secret past this one via join request
  kv::Version up_to_ledger_secret_seqno = 4;
  network.ledger_secrets->set_secret(
    up_to_ledger_secret_seqno, make_ledger_secret());

  // Node certificate
  crypto::KeyPairPtr kp = crypto::make_key_pair();
  const auto caller = kp->self_sign("CN=Joiner", valid_from, valid_to);
  const auto node_public_encryption_key =
    crypto::make_key_pair()->public_key_pem();

  INFO("Try to join with a different consensus");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;
    join_input.consensus_type = ConsensusType::BFT;
    const auto response =
      frontend_process(frontend, join_input, "join", caller);

    check_error(response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(
      response,
      fmt::format(
        "Node requested to join with consensus type {} but "
        "current consensus type is {}",
        ConsensusType::BFT,
        ConsensusType::CFT));
  }

  INFO("Add first node before a service exists");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;
    const auto response =
      frontend_process(frontend, join_input, "join", caller);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    check_error_message(response, "No service is available to accept new node");
  }

  gen.create_service(network.identity->cert, ccf::TxID{});
  REQUIRE(gen_tx.commit() == kv::CommitResult::SUCCESS);
  auto tx = network.tables->create_tx();

  INFO("Add first node which should be trusted straight away");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;
    // Join input does not include CSR (1.x)
    join_input.certificate_signing_request = std::nullopt;

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.has_value());
    CHECK(response.network_info->identity == *network.identity.get());
    CHECK(response.network_info->public_only == false);
    // No endorsed certificate since no CSR was passed in
    CHECK(response.network_info->endorsed_certificate == std::nullopt);

    auto pk_der = kp->public_key_der();
    const NodeId node_id = crypto::Sha256Hash(pk_der).hex_str();
    auto nodes = tx.rw(network.nodes);
    auto node_info = nodes->get(node_id);

    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::TRUSTED);
    CHECK(kp->public_key_pem() == node_info->public_key);
  }

  INFO("Adding the same node should return the same result");
  {
    // Even if rekey occurs in between, the same ledger secrets should be
    // returned
    network.ledger_secrets->set_secret(
      up_to_ledger_secret_seqno + 1, make_ledger_secret());

    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.has_value());
    require_ledger_secrets_equal(
      response.network_info->ledger_secrets,
      network.ledger_secrets->get(tx, up_to_ledger_secret_seqno));
    CHECK(response.network_info->identity == *network.identity.get());
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    crypto::KeyPairPtr kp = crypto::make_key_pair();
    auto v = crypto::make_verifier(
      kp->self_sign("CN=Other Joiner", valid_from, valid_to));
    const auto new_caller = v->cert_pem();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response =
      frontend_process(frontend, join_input, "join", new_caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(http_response, "A node with the same node address");
  }
}

TEST_CASE("Add a node to an open service")
{
  NetworkState network;
  auto gen_tx = network.tables->create_tx();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);
  GenesisGenerator gen(network, gen_tx);

  ShareManager share_manager(network);
  StubNodeContext context;
  context.node_operation->is_public = true;
  NodeRpcFrontend frontend(network, context);
  frontend.open();

  network.identity = make_test_network_ident();
  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  network.ledger_secrets->init();

  // New node should not be given ledger secret past this one via join request
  kv::Version up_to_ledger_secret_seqno = 4;
  network.ledger_secrets->set_secret(
    up_to_ledger_secret_seqno, make_ledger_secret());

  gen.create_service(network.identity->cert, ccf::TxID{});
  gen.init_configuration({1});
  gen.activate_member(gen.add_member(
    {member_cert, crypto::make_rsa_key_pair()->public_key_pem()}));
  REQUIRE(gen.open_service());
  REQUIRE(gen_tx.commit() == kv::CommitResult::SUCCESS);

  // Node certificate
  crypto::KeyPairPtr kp = crypto::make_key_pair();
  const auto caller = kp->self_sign("CN=Joiner", valid_from, valid_to);

  std::optional<NodeInfo> node_info;
  auto tx = network.tables->create_tx();

  const auto node_public_encryption_key =
    crypto::make_key_pair()->public_key_pem();

  JoinNetworkNodeToNode::In join_input;
  join_input.public_encryption_key = node_public_encryption_key;
  join_input.certificate_signing_request = kp->create_csr("CN=Joiner");

  INFO("Add node once service is open");
  {
    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(!response.network_info.has_value());

    auto pk_der = kp->public_key_der();
    const NodeId node_id = crypto::Sha256Hash(pk_der).hex_str();
    auto nodes = tx.rw(network.nodes);
    node_info = nodes->get(node_id);
    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::PENDING);
    CHECK(kp->public_key_pem() == node_info->public_key);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    crypto::KeyPairPtr kp = crypto::make_key_pair();
    auto v =
      crypto::make_verifier(kp->self_sign("CN=Joiner", valid_from, valid_to));
    const auto new_caller = v->cert_pem();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response =
      frontend_process(frontend, join_input, "join", new_caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(http_response, "A node with the same node address");
  }

  INFO("Try to join again without being trusted");
  {
    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    // The network secrets are still not available to the joining node
    CHECK(!response.network_info.has_value());
  }

  INFO("Trust node and attempt to join");
  {
    // In a real scenario, nodes are trusted via member governance.
    GenesisGenerator g(network, tx);
    auto joining_node_id = ccf::compute_node_id_from_kp(kp);
    g.trust_node(joining_node_id, network.ledger_secrets->get_latest(tx).first);
    const auto dummy_endorsed_certificate = crypto::make_key_pair()->self_sign(
      "CN=dummy endorsed certificate", valid_from, valid_to);
    auto endorsed_certificate = tx.rw(network.node_endorsed_certificates);
    endorsed_certificate->put(joining_node_id, {dummy_endorsed_certificate});
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    // In the meantime, a new ledger secret is added. The new ledger secret
    // should not be passed to the new joiner via the join
    network.ledger_secrets->set_secret(
      up_to_ledger_secret_seqno + 1, make_ledger_secret());

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    auto tx = network.tables->create_tx();
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.has_value());
    require_ledger_secrets_equal(
      response.network_info->ledger_secrets,
      network.ledger_secrets->get(tx, up_to_ledger_secret_seqno));
    CHECK(response.network_info->identity == *network.identity.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info->public_only == true);
    CHECK(response.network_info->endorsed_certificate.has_value());
    CHECK(
      response.network_info->endorsed_certificate.value() ==
      dummy_endorsed_certificate);
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
