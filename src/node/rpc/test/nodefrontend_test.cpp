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
  RpcFrontend& frontend,
  const json& json_params,
  const std::string& method,
  const Cert& caller)
{
  auto serialise_request =
    pack(create_json_req(json_params, NodeProcs::JOIN), Pack::MsgPack);

  enclave::RPCContext rpc_ctx(0, caller);
  auto serialised_response = frontend.process(rpc_ctx, serialise_request);

  return unpack(serialised_response, Pack::MsgPack);
}

TEST_CASE("Add a node to an opening service")
{
  NetworkState network;
  GenesisGenerator gen(network);
  gen.init_values();

  StubNodeState node;
  NodeCallRpcFrontend frontend(network, node);

  network.secrets = std::make_unique<NetworkSecrets>("CN=The CA");

  gen.create_service({});
  gen.finalize();

  // Node certificate
  tls::KeyPairPtr kp = tls::make_key_pair();
  auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
  Cert caller = v->raw_cert_data();

  INFO("Add first node which should be trusted straight away");
  {
    JoinNetworkNodeToNode::In join_input;

    auto response = jsonrpc::Response<JoinNetworkNodeToNode::Out>(
      frontend_process(frontend, join_input, NodeProcs::JOIN, caller));

    CHECK(
      response->network_info.network_secrets == network.secrets->get_current());
    CHECK(response->network_info.version == 0);
    CHECK(response->node_status == NodeStatus::TRUSTED);

    Store::Tx tx;
    const NodeId node_id = response->network_info.node_id;
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
      response->network_info.network_secrets == network.secrets->get_current());
    CHECK(response->network_info.version == 0);
    CHECK(response->node_status == NodeStatus::TRUSTED);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    tls::KeyPairPtr kp = tls::make_key_pair();
    auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
    Cert caller = v->raw_cert_data();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;

    auto resp = frontend_process(frontend, join_input, NodeProcs::JOIN, caller);

    check_error(resp, StandardErrorCodes::INVALID_PARAMS);
    check_error_message(resp, "A node with the same node host");
  }
}

// TEST_CASE("Add a node in an open service")
// {
//   NetworkState network;
//   GenesisGenerator gen(network);
//   gen.init_values();

//   StubNodeState node;
//   NodeCallRpcFrontend frontend(network, node);

//   network.secrets = std::make_unique<NetworkSecrets>("CN=The CA");

//   gen.create_service({});
//   gen.open_service();
//   gen.finalize();

//   INFO("Add node once service is open");
//   {
//     tls::KeyPairPtr kp = tls::make_key_pair();
//     auto v = tls::make_verifier(kp->self_sign(fmt::format("CN=nodes")));
//     Cert caller = v->raw_cert_data();

//     JoinNetworkNodeToNode::In join_input;

//     auto response = jsonrpc::Response<JoinNetworkNodeToNode::Out>(
//       frontend_process(frontend, join_input, NodeProcs::JOIN, caller));

//     // TODO:
//     // 1. Check that no secrets have been given
//     // 2. Check that node has been added as pending in the KV

//     Store::Tx tx;
//     const NodeId node_id = response->node_id;
//     auto nodes_view = tx.get_view(network.nodes);
//     auto node_info = nodes_view->get(node_id);
//     CHECK(node_info.has_value());
//     CHECK(node_info->status == NodeStatus::PENDING);
//     CHECK(
//       v->cert_pem().str() ==
//       std::string({node_info->cert.data(),
//                    node_info->cert.data() + node_info->cert.size()}));

//     // TODO: Add node as TRUSTED with a kv write
//     node_info->status = NodeStatus::TRUSTED;
//     nodes_view->put(0, node_info.value());

//     // TODO: Try to join again
//     // 1. Network secrets should be given, along with version and node_id

//   }
// }

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