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
          tx_scripts->put(rs.first, lua::compile(rs.second));
        else
          tx_scripts->put(rs.first, rs.second);
      }
    }

  public:
    GenesisGenerator(NetworkTables& tables_) : tables(tables_) {}

    void init_values()
    {
      auto v = tx.get_view(tables.values);
      for (int id_type = 0; id_type < ValueIds::END_ID; id_type++)
        v->put(id_type, 0);
    }

    auto finalize()
    {
      return tx.commit();
    }

    void retire_active_nodes()
    {
      auto nodes_view = tx.get_view(tables.nodes);

      std::map<NodeId, NodeInfo> nodes_to_delete;
      nodes_view->foreach(
        [&nodes_to_delete](const NodeId& nid, const NodeInfo& ni) {
          // Only retire nodes that have not already been retired
          if (ni.status != NodeStatus::RETIRED)
            nodes_to_delete[nid] = ni;
          return true;
        });

      for (auto [nid, ni] : nodes_to_delete)
      {
        ni.status = NodeStatus::RETIRED;
        nodes_view->put(nid, ni);
      }
    }

    auto add_member(
      const std::vector<uint8_t>& member_cert,
      MemberStatus member_status = MemberStatus::ACTIVE)
    {
      auto member_id =
        get_next_id(tx.get_view(tables.values), ValueIds::NEXT_MEMBER_ID);
      auto [members_view, member_certs_view] =
        tx.get_view(tables.members, tables.member_certs);
      members_view->put(member_id, {member_cert, member_status});
      member_certs_view->put(member_cert, member_id);
      return member_id;
    }

    auto add_user(const std::vector<uint8_t>& user_cert)
    {
      auto user_id =
        get_next_id(tx.get_view(tables.values), ValueIds::NEXT_USER_ID);
      auto [users_view, user_certs_view] =
        tx.get_view(tables.users, tables.user_certs);
      users_view->put(user_id, {user_cert});
      user_certs_view->put(user_cert, user_id);
      return user_id;
    }

    auto add_node(const NodeInfo& node_info)
    {
      auto node_id =
        get_next_id(tx.get_view(tables.values), ValueIds::NEXT_NODE_ID);

      auto raw_cert = tls::make_verifier(node_info.cert)->raw_cert_data();

      auto node_view = tx.get_view(tables.nodes);
      node_view->put(node_id, node_info);
      return node_id;
    }

    void create_service(
      const std::vector<uint8_t>& network_cert, kv::Version version = 1)
    {
      auto service_view = tx.get_view(tables.service);
      service_view->put(0, {version, network_cert, ServiceStatus::OPENING});
    }

    // TODO: This function is very similar to open_network() in nodestate.h
    // Change this as part of https://github.com/microsoft/CCF/issues/320 so
    // that this class can either take an existing Store::Tx or create a new
    // one
    bool open_service()
    {
      auto service_view = tx.get_view(tables.service);

      auto active_service = service_view->get(0);
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return false;
      }

      if (active_service->status != ServiceStatus::OPENING)
      {
        LOG_FAIL_FMT("Could not open current service: status is not OPENING");
        return false;
      }

      active_service->status = ServiceStatus::OPEN;
      service_view->put(0, active_service.value());

      return true;
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

    void set_whitelist(WlIds id, Whitelist wl)
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
      auto codeid_view = tx.get_view(tables.code_ids);
      codeid_view->put(node_code_id, CodeStatus::ACCEPTED);
    }
  };
}