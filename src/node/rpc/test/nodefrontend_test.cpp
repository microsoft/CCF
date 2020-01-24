// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#include "ds/logger.h"
#include "nlohmann/json.hpp"
#include "node/genesisgen.h"
#include "node/rpc/jsonrpc.h"
#include "node/rpc/nodefrontend.h"
#include "node_stub.h"
#include "tls/pem.h"

using namespace ccf;
using namespace nlohmann;
using namespace jsonrpc;

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

json create_json_req(const json& params, const std::string& method_name)
{
  json j;
  j[JSON_RPC] = RPC_VERSION;
  j[ID] = 1;
  j[METHOD] = method_name;
  if (!params.is_null())
    j[PARAMS] = params;
  return j;
}

template <typename E>
void check_error(const nlohmann::json& j, const E expected)
{
  CHECK(
    j[ERR][CODE].get<jsonrpc::ErrorBaseType>() ==
    static_cast<jsonrpc::ErrorBaseType>(expected));
}

void check_error_message(const nlohmann::json& j, const std::string& msg)
{
  CHECK(j[ERR][MESSAGE].get<std::string>().find(msg) != std::string::npos);
}

const json frontend_process(
  NodeRpcFrontend& frontend,
  const json& json_params,
  const std::string& method,
  const Cert& caller)
{
  auto req = create_json_req(json_params, method);
  auto serialise_request = pack(req, Pack::Text);

  const enclave::SessionContext session(0, caller);
  auto rpc_ctx = enclave::make_rpc_context(session, serialise_request);
  auto serialised_response = frontend.process(rpc_ctx);

  return unpack(serialised_response.value(), Pack::Text);
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

  // Node certificate
  tls::KeyPairPtr kp = tls::make_key_pair();
  auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
  Cert caller = v->der_cert_data();

  INFO("Add first node before a service exists");
  {
    JoinNetworkNodeToNode::In join_input;
    auto response_j =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(response_j, StandardErrorCodes::INTERNAL_ERROR);
    check_error_message(
      response_j, "No service is available to accept new node");
  }

  gen.create_service({});
  gen.finalize();

  INFO("Add first node which should be trusted straight away");
  {
    JoinNetworkNodeToNode::In join_input;

    auto response = jsonrpc::Response<JoinNetworkNodeToNode::Out>(
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller));

    CHECK(
      response->network_info.ledger_secrets == *network.ledger_secrets.get());
    CHECK(response->network_info.identity == *network.identity.get());
    CHECK(response->node_status == NodeStatus::TRUSTED);
    CHECK(response->public_only == false);

    Store::Tx tx;
    const NodeId node_id = response->node_id;
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

    auto response = jsonrpc::Response<JoinNetworkNodeToNode::Out>(
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller));

    CHECK(
      response->network_info.ledger_secrets == *network.ledger_secrets.get());
    CHECK(response->network_info.identity == *network.identity.get());
    CHECK(response->node_status == NodeStatus::TRUSTED);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    tls::KeyPairPtr kp = tls::make_key_pair();
    auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
    Cert caller = v->der_cert_data();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;

    auto response_j =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(response_j, StandardErrorCodes::INVALID_PARAMS);
    check_error_message(response_j, "A node with the same node host");
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
    auto response_j =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    CHECK(response_j[RESULT].find("network_info") == response_j[RESULT].end());
    auto response = jsonrpc::Response<JoinNetworkNodeToNode::Out>(response_j);

    auto node_id = response->node_id;

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

    auto response_j =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(response_j, StandardErrorCodes::INVALID_PARAMS);
    check_error_message(response_j, "A node with the same node host");
  }

  INFO("Try to join again without being trusted");
  {
    auto response_j =
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    // The network secrets are still not available to the joining node
    CHECK(response_j[RESULT].find("network_info") == response_j[RESULT].end());
  }

  INFO("Trust node and attempt to join");
  {
    // In a real scenario, nodes are trusted via member governance.
    node_info->status = NodeStatus::TRUSTED;
    auto nodes_view = tx.get_view(network.nodes);
    nodes_view->put(0, node_info.value());
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    auto response = jsonrpc::Response<JoinNetworkNodeToNode::Out>(
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller));

    CHECK(
      response->network_info.ledger_secrets == *network.ledger_secrets.get());
    CHECK(response->network_info.identity == *network.identity.get());
    CHECK(response->node_status == NodeStatus::TRUSTED);
    CHECK(response->public_only == true);
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