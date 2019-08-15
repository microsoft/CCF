// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "luainterp/luautil.h"
#include "node/entities.h"
#include "node/members.h"
#include "node/networktables.h"
#include "node/nodes.h"
#include "node/rpc/consts.h"
#include "node/rpc/jsonrpc.h"
#include "node/rpc/serialization.h"
#include "node/values.h"

#include <algorithm>
#include <fstream>
#include <ostream>

class GenesisGenerator : public ccf::NetworkTables
{
protected:
  ccf::Store::Tx tx;

  void init_values()
  {
    auto v = tx.get_view(values);
    for (int id_type = 0; id_type < ccf::ValueIds::END_ID; id_type++)
      v->put(id_type, 0);
  }

  template <typename T>
  void set_scripts(
    std::map<std::string, std::string> scripts,
    T& table,
    const bool compile = false)
  {
    auto tx_scripts = tx.get_view(table);
    for (auto& rs : scripts)
    {
      if (compile)
        tx_scripts->put(rs.first, ccf::lua::compile(rs.second));
      else
        tx_scripts->put(rs.first, rs.second);
    }
  }

public:
  GenesisGenerator() : tx(tables->next_version())
  {
    init_values();
  }

  virtual ~GenesisGenerator() {}

  std::vector<uint8_t> finalize_raw()
  {
    auto [success, reqid, vtx0] = tx.commit_reserved();
    if (success)
      throw std::logic_error("Could not commit tx0.");
    return vtx0;
  }

  bool finalize(
    const std::string& tx0_file, const std::string& start_network_file)
  {
    auto vtx0 = finalize_raw();
    // write tx0
    std::ofstream otx0(tx0_file, std::ios::trunc | std::ios::binary);
    std::string sd(vtx0.begin(), vtx0.end());
    otx0.write((char*)sd.data(), sd.size());

    ccf::Store::Tx tx;
    auto nodes_view = tx.get_view(nodes);
    // write startNetwork rpc
    jsonrpc::ProcedureCall<ccf::StartNetwork::In> rpc;
    rpc.id = 1;
    rpc.method = ccf::ManagementProcs::START_NETWORK;
    rpc.params.tx0 = vtx0;
    ccf::NodeId start_node = ccf::INVALID_ID;

    nodes_view->foreach(
      [&start_node](const ccf::NodeId& id, const ccf::NodeInfo& v) {
        start_node = id;
        return false;
      });

    rpc.params.id = start_node;
    std::ofstream ostartnet(start_network_file, std::ios::trunc);
    ostartnet << nlohmann::json(rpc);

    return true;
  }

  void create_join_rpc(
    const std::string join_host,
    const std::string join_port,
    const std::string& join_network_file,
    const std::vector<uint8_t>& network_cert)
  {
    jsonrpc::ProcedureCall<ccf::JoinNetwork::In> rpc;
    rpc.id = 1;
    rpc.method = ccf::ManagementProcs::JOIN_NETWORK;
    rpc.params.hostname = join_host;
    rpc.params.service = join_port;
    rpc.params.network_cert = network_cert;

    std::ofstream ojoinnet(join_network_file, std::ios::trunc);
    ojoinnet << nlohmann::json(rpc);
  }

  auto add_member(
    const std::vector<uint8_t>& member_cert,
    ccf::MemberStatus member_status = ccf::MemberStatus::ACTIVE)
  {
    // generate member id and create entry in members table
    auto member_id =
      get_next_id(tx.get_view(values), ccf::ValueIds::NEXT_MEMBER_ID);
    auto tx_members = tx.get_view(members);
    tx_members->put(member_id, {member_status});

    // store pubk
    auto tx_members_info = tx.get_view(member_certs);
    tx_members_info->put(member_cert, member_id);
    return member_id;
  }

  auto add_user(const std::vector<uint8_t>& user_cert)
  {
    // generate user id and create entry in users table
    auto user_id =
      get_next_id(tx.get_view(values), ccf::ValueIds::NEXT_USER_ID);

    // store pubk
    auto tx_users_certs = tx.get_view(user_certs);
    tx_users_certs->put(user_cert, user_id);
    return user_id;
  }

  auto add_node(const ccf::NodeInfo& ni)
  {
    auto node_id =
      get_next_id(tx.get_view(values), ccf::ValueIds::NEXT_NODE_ID);
    // store pubk
    auto verifier = tls::make_verifier(ni.cert);
    auto tx_node_certs = tx.get_view(node_certs);
    tx_node_certs->put(verifier->raw_cert_data(), node_id);

    auto tx_nodes = tx.get_view(nodes);
    tx_nodes->put(node_id, ni);
    return node_id;
  }

  void set_whitelist(ccf::WlIds id, ccf::Whitelist wl)
  {
    tx.get_view(whitelists)->put(id, wl);
  }

  void set_gov_scripts(std::map<std::string, std::string> scripts)
  {
    // don't compile, because gov scripts are important functionally but not
    // performance-wise
    set_scripts(scripts, gov_scripts, false);
  }

  void set_app_scripts(std::map<std::string, std::string> scripts)
  {
    set_scripts(scripts, app_scripts, true);
  }
};