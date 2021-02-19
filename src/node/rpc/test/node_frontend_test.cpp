// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/logger.h"
#include "nlohmann/json.hpp"
#include "node/genesis_gen.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/serdes.h"
#include "node_stub.h"
#include "tls/pem.h"
#include "tls/verifier.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace ccf;
using namespace nlohmann;
using namespace serdes;

using TResponse = http::SimpleResponseProcessor::Response;

auto kp = tls::make_key_pair();
auto member_cert = kp -> self_sign("CN=name_member");
auto node_id = 0;

void check_error(const TResponse& r, http_status expected)
{
  CHECK(r.status == expected);
}

void check_error_message(const TResponse& r, const std::string& msg)
{
  const std::string body_s(r.body.begin(), r.body.end());
  CHECK(body_s.find(msg) != std::string::npos);
}

TResponse frontend_process(
  NodeRpcFrontend& frontend,
  const json& json_params,
  const std::string& method,
  const tls::Pem& caller)
{
  http::Request r(method);
  const auto body = json_params.is_null() ?
    std::vector<uint8_t>() :
    serdes::pack(json_params, Pack::Text);
  r.set_body(&body);
  auto serialise_request = r.build_request();

  auto session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, caller.raw());
  auto rpc_ctx = enclave::make_rpc_context(session, serialise_request);
  auto serialised_response = frontend.process(rpc_ctx);

  CHECK(serialised_response.has_value());

  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  parser.execute(serialised_response->data(), serialised_response->size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

template <typename T>
T parse_response_body(const TResponse& r)
{
  const auto body_j = serdes::unpack(r.body, serdes::Pack::Text);
  return body_j.get<T>();
}

TEST_CASE("Add a node to an opening service")
{
  NetworkState network;
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  ShareManager share_manager(network);
  StubNodeState node;
  NodeRpcFrontend frontend(network, node);
  frontend.open();

  network.identity = std::make_unique<NetworkIdentity>();
  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>(node_id);
  network.ledger_secrets->init();

  // New node should not be given ledger secret past this one via join request
  kv::Version up_to_ledger_secret_seqno = 4;
  network.ledger_secrets->set_secret(
    up_to_ledger_secret_seqno, make_ledger_secret());

  // Node certificate
  tls::KeyPairPtr kp = tls::make_key_pair();
  const auto caller = kp->self_sign(fmt::format("CN=nodes"));
  const auto node_public_encryption_key =
    tls::make_key_pair()->public_key_pem();

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

  gen.create_service({});
  gen.finalize();
  auto tx = network.tables->create_tx();

  INFO("Add first node which should be trusted straight away");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(
      response.network_info.ledger_secrets == network.ledger_secrets->get(tx));
    CHECK(response.network_info.identity == *network.identity.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.public_only == false);

    const NodeId node_id = response.node_id;
    auto nodes = tx.rw(network.nodes);
    auto node_info = nodes->get(node_id);

    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::TRUSTED);
    CHECK(caller == node_info->cert);
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

    CHECK(
      response.network_info.ledger_secrets ==
      network.ledger_secrets->get(tx, up_to_ledger_secret_seqno));
    CHECK(response.network_info.identity == *network.identity.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    tls::KeyPairPtr kp = tls::make_key_pair();
    auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
    const auto caller = v->cert_der();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response = frontend_process(frontend, join_input, "join", caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(http_response, "A node with the same node host");
  }
}

TEST_CASE("Add a node to an open service")
{
  NetworkState network;
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  ShareManager share_manager(network);
  StubNodeState node;
  node.set_is_public(true);
  NodeRpcFrontend frontend(network, node);
  frontend.open();

  network.identity = std::make_unique<NetworkIdentity>();

  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>(node_id);
  network.ledger_secrets->init();

  // New node should not be given ledger secret past this one via join request
  kv::Version up_to_ledger_secret_seqno = 4;
  network.ledger_secrets->set_secret(
    up_to_ledger_secret_seqno, make_ledger_secret());

  gen.create_service({});
  gen.init_configuration({1});
  gen.activate_member(
    gen.add_member({member_cert, tls::make_rsa_key_pair()->public_key_pem()}));
  REQUIRE(gen.open_service());
  gen.finalize();

  // Node certificate
  tls::KeyPairPtr kp = tls::make_key_pair();
  const auto caller = kp->self_sign(fmt::format("CN=nodes"));

  std::optional<NodeInfo> node_info;
  auto tx = network.tables->create_tx();

  JoinNetworkNodeToNode::In join_input;

  INFO("Add node once service is open");
  {
    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(response.network_info.identity.priv_key.empty());

    auto node_id = response.node_id;

    auto nodes = tx.rw(network.nodes);
    node_info = nodes->get(node_id);
    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::PENDING);
    CHECK(caller == node_info->cert);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    tls::KeyPairPtr kp = tls::make_key_pair();
    auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
    const auto caller = v->cert_der();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;

    auto http_response = frontend_process(frontend, join_input, "join", caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(http_response, "A node with the same node host");
  }

  INFO("Try to join again without being trusted");
  {
    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    // The network secrets are still not available to the joining node
    CHECK(response.network_info.identity.priv_key.empty());
  }

  INFO("Trust node and attempt to join");
  {
    // In a real scenario, nodes are trusted via member governance.
    GenesisGenerator g(network, tx);
    g.trust_node(0, network.ledger_secrets->get_latest(tx).first);
    REQUIRE(g.finalize() == kv::CommitResult::SUCCESS);

    // In the meantime, a new ledger secret is added. The new ledger secret
    // should not be passed to the new joiner via the join
    network.ledger_secrets->set_secret(
      up_to_ledger_secret_seqno + 1, make_ledger_secret());

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    auto tx = network.tables->create_tx();
    CHECK(
      response.network_info.ledger_secrets ==
      network.ledger_secrets->get(tx, up_to_ledger_secret_seqno));
    CHECK(response.network_info.identity == *network.identity.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.public_only == true);
  }
}