// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT
#include "crypto/crypto_box.h"
#include "ds/logger.h"
#include "nlohmann/json.hpp"
#include "node/genesis_gen.h"
#include "node/rpc/json_rpc.h"
#include "node/rpc/node_frontend.h"
#include "node_stub.h"
#include "tls/pem.h"
#include "tls/verifier.h"

#include <doctest/doctest.h>

using namespace ccf;
using namespace nlohmann;
using namespace jsonrpc;

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

using TResponse = http::SimpleResponseProcessor::Response;

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
  const Cert& caller)
{
  http::Request r(method);
  const auto body = json_params.is_null() ?
    std::vector<uint8_t>() :
    jsonrpc::pack(json_params, Pack::Text);
  r.set_body(&body);
  auto serialise_request = r.build_request();

  auto session = std::make_shared<enclave::SessionContext>(0, caller);
  auto rpc_ctx = enclave::make_rpc_context(session, serialise_request);
  auto serialised_response = frontend.process(rpc_ctx);

  CHECK(serialised_response.has_value());

  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  const auto parsed_count =
    parser.execute(serialised_response->data(), serialised_response->size());
  REQUIRE(parsed_count == serialised_response->size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

template <typename T>
T parse_response_body(const TResponse& r)
{
  const auto body_j = jsonrpc::unpack(r.body, jsonrpc::Pack::Text);
  return body_j.get<T>();
}

TEST_CASE("Add a node to an opening service")
{
  NetworkState network;
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  StubNodeState node;
  NodeRpcFrontend frontend(network, node);
  frontend.open();

  network.identity = std::make_unique<NetworkIdentity>();
  network.ledger_secrets = std::make_shared<LedgerSecrets>();
  network.ledger_secrets->set_secret(0, std::vector<uint8_t>(16, 0x42));
  network.ledger_secrets->set_secret(10, std::vector<uint8_t>(16, 0x44));
  network.encryption_key = std::make_unique<NetworkEncryptionKey>();

  // Node certificate
  tls::KeyPairPtr kp = tls::make_key_pair();
  auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
  Cert caller = v->der_cert_data();

  INFO("Try to join with a different consensus");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.consensus_type = ConsensusType::PBFT;
    const auto response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(
      response,
      fmt::format(
        "Node requested to join with consensus type {} but "
        "current consensus type is {}",
        ConsensusType::PBFT,
        ConsensusType::RAFT));
  }

  INFO("Add first node before a service exists");
  {
    JoinNetworkNodeToNode::In join_input;
    const auto response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    check_error_message(response, "No service is available to accept new node");
  }

  gen.create_service({});
  gen.finalize();

  INFO("Add first node which should be trusted straight away");
  {
    JoinNetworkNodeToNode::In join_input;

    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(
      response.network_info.ledger_secrets == *network.ledger_secrets.get());
    CHECK(response.network_info.identity == *network.identity.get());
    CHECK(
      response.network_info.encryption_key == *network.encryption_key.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.public_only == false);

    Store::Tx tx;
    const NodeId node_id = response.node_id;
    auto nodes_view = tx.get_view(network.nodes);
    auto node_info = nodes_view->get(node_id);

    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::TRUSTED);
    CHECK(
      v->cert_pem().str() ==
      std::string({node_info->cert.data(),
                   node_info->cert.data() + node_info->cert.size()}));
  }

  INFO("Adding the same node should return the same result");
  {
    JoinNetworkNodeToNode::In join_input;

    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(
      response.network_info.ledger_secrets == *network.ledger_secrets.get());
    CHECK(response.network_info.identity == *network.identity.get());
    CHECK(
      response.network_info.encryption_key == *network.encryption_key.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    tls::KeyPairPtr kp = tls::make_key_pair();
    auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
    Cert caller = v->der_cert_data();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;

    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(http_response, "A node with the same node host");
  }
}

TEST_CASE("Add a node to an open service")
{
  NetworkState network;
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  StubNodeState node;
  node.set_is_public(true);
  NodeRpcFrontend frontend(network, node);
  frontend.open();

  network.identity = std::make_unique<NetworkIdentity>();
  network.ledger_secrets = std::make_shared<LedgerSecrets>();
  network.ledger_secrets->set_secret(0, std::vector<uint8_t>(16, 0x42));
  network.ledger_secrets->set_secret(10, std::vector<uint8_t>(16, 0x44));
  network.encryption_key = std::make_unique<NetworkEncryptionKey>();

  gen.create_service({});
  gen.open_service();
  gen.finalize();

  // Node certificate
  tls::KeyPairPtr kp = tls::make_key_pair();
  auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
  Cert caller = v->der_cert_data();

  std::optional<NodeInfo> node_info;
  Store::Tx tx;

  JoinNetworkNodeToNode::In join_input;

  INFO("Add node once service is open");
  {
    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(response.network_info.identity.priv_key.empty());

    auto node_id = response.node_id;

    auto nodes_view = tx.get_view(network.nodes);
    node_info = nodes_view->get(node_id);
    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::PENDING);
    CHECK(
      v->cert_pem().str() ==
      std::string({node_info->cert.data(),
                   node_info->cert.data() + node_info->cert.size()}));
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    tls::KeyPairPtr kp = tls::make_key_pair();
    auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
    Cert caller = v->der_cert_data();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;

    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(http_response, "A node with the same node host");
  }

  INFO("Try to join again without being trusted");
  {
    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    // The network secrets are still not available to the joining node
    CHECK(response.network_info.identity.priv_key.empty());
  }

  INFO("Trust node and attempt to join");
  {
    // In a real scenario, nodes are trusted via member governance.
    node_info->status = NodeStatus::TRUSTED;
    auto nodes_view = tx.get_view(network.nodes);
    nodes_view->put(0, node_info.value());
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    auto http_response =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(
      response.network_info.ledger_secrets == *network.ledger_secrets.get());
    CHECK(response.network_info.identity == *network.identity.get());
    CHECK(
      response.network_info.encryption_key == *network.encryption_key.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.public_only == true);
  }
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