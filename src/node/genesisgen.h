// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "codeid.h"
#include "entities.h"
#include "luainterp/luainterp.h"
#include "luainterp/luautil.h"
#include "members.h"
#include "networktables.h"
#include "nodeinfonetwork.h"
#include "nodes.h"
#include "rpc/consts.h"
#include "rpc/jsonrpc.h"
#include "runtime_config/default_whitelists.h"
#include "tls/keypair.h"
#include "values.h"

#include <algorithm>
#include <fstream>
#include <ostream>

namespace ccf
{
  class GenesisGenerator
  {
    NetworkTables& tables;

    Store::Tx tx;

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
    GenesisGenerator(NetworkTables& tables_) : tables(tables_) {}

    void init_values()
    {
      auto v = tx.get_view(tables.values);
      for (int id_type = 0; id_type < ccf::ValueIds::END_ID; id_type++)
        v->put(id_type, 0);
    }

    auto finalize()
    {
      return tx.commit();
    }

    void delete_active_nodes()
    {
      auto [nodes_view, node_certs_view] =
        tx.get_view(tables.nodes, tables.node_certs);

      std::map<NodeId, NodeInfo> nodes_to_delete;
      nodes_view->foreach(
        [&nodes_to_delete](const NodeId& nid, const NodeInfo& ni) {
          // Only retire nodes that have not already been retired
          if (ni.status != ccf::NodeStatus::RETIRED)
            nodes_to_delete[nid] = ni;
          return true;
        });

      for (auto [nid, ni] : nodes_to_delete)
      {
        ni.status = ccf::NodeStatus::RETIRED;
        nodes_view->put(nid, ni);
      }

      std::vector<Cert> certs_to_delete;
      node_certs_view->foreach(
        [&certs_to_delete](const Cert& cstr, const NodeId& _) {
          certs_to_delete.push_back(cstr);
          return true;
        });
      for (Cert& cstr : certs_to_delete)
      {
        node_certs_view->remove(cstr);
      }
    }

    auto add_member(
      const std::vector<uint8_t>& member_cert,
      ccf::MemberStatus member_status = ccf::MemberStatus::ACTIVE)
    {
      // generate member id and create entry in members table
      auto member_id =
        get_next_id(tx.get_view(tables.values), ccf::ValueIds::NEXT_MEMBER_ID);
      auto members_view = tx.get_view(tables.members);
      members_view->put(member_id, {member_status});

      // store pubk
      auto member_certs_view = tx.get_view(tables.member_certs);
      member_certs_view->put(member_cert, member_id);
      return member_id;
    }

    auto add_user(const std::vector<uint8_t>& user_cert)
    {
      // generate user id and create entry in users table
      auto user_id =
        get_next_id(tx.get_view(tables.values), ccf::ValueIds::NEXT_USER_ID);

      // store pubk
      auto user_certs_view = tx.get_view(tables.user_certs);
      user_certs_view->put(user_cert, user_id);
      return user_id;
    }

    auto add_node(const ccf::NodeInfo& ni)
    {
      auto node_id =
        get_next_id(tx.get_view(tables.values), ccf::ValueIds::NEXT_NODE_ID);

      auto raw_cert = tls::make_verifier(ni.cert)->raw_cert_data();
      auto node_certs_view = tx.get_view(tables.node_certs);
      node_certs_view->put(raw_cert, node_id);

      auto node_view = tx.get_view(tables.nodes);
      node_view->put(node_id, ni);
      return node_id;
    }

    void trust_node(NodeId node_id)
    {
      auto nodes_view = tx.get_view(tables.nodes);
      auto node_info = nodes_view->get(node_id);
      if (node_info.has_value())
      {
        node_info->status = NodeStatus::TRUSTED;
        nodes_view->put(node_id, node_info.value());
      }
      else
      {
        LOG_FAIL_FMT("Unknown node {} could not be trusted");
      }
    }

    auto get_last_signature()
    {
      auto sig_view = tx.get_view(tables.signatures);
      return sig_view->get(0);
    }

    void set_whitelist(ccf::WlIds id, ccf::Whitelist wl)
    {
      tx.get_view(tables.whitelists)->put(id, wl);
    }

    void set_gov_scripts(std::map<std::string, std::string> scripts)
    {
      // don't compile, because gov scripts are important functionally but not
      // performance-wise
      set_scripts(scripts, tables.gov_scripts, false);
    }

    void set_app_scripts(std::map<std::string, std::string> scripts)
    {
      set_scripts(scripts, tables.app_scripts, true);
    }

    void trust_code_id(CodeDigest& node_code_id)
    {
      auto codeid_view = tx.get_view(tables.code_id);
      codeid_view->put(node_code_id, CodeStatus::ACCEPTED);
    }
  };
}