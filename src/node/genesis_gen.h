// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "code_id.h"
#include "crypto/hash.h"
#include "entities.h"
#include "kv/tx.h"
#include "ledger_secrets.h"
#include "lua_interp/lua_interp.h"
#include "lua_interp/lua_util.h"
#include "members.h"
#include "network_tables.h"
#include "node_info_network.h"
#include "nodes.h"
#include "runtime_config/default_whitelists.h"
#include "tls/verifier.h"
#include "values.h"

#include <algorithm>
#include <fstream>
#include <ostream>

namespace ccf
{
  class GenesisGenerator
  {
    NetworkTables& tables;

    kv::Tx& tx;

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
    GenesisGenerator(NetworkTables& tables_, kv::Tx& tx_) :
      tables(tables_),
      tx(tx_)
    {}

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

    auto add_consensus(ConsensusType consensus_type)
    {
      auto cv = tx.get_view(tables.consensus);
      cv->put(0, consensus_type);
    }

    auto get_active_recovery_members()
    {
      auto members_view = tx.get_view(tables.members);
      std::map<MemberId, tls::Pem> active_members_info;

      members_view->foreach(
        [&active_members_info](const MemberId& mid, const MemberInfo& mi) {
          if (mi.status == MemberStatus::ACTIVE && mi.is_recovery())
          {
            active_members_info[mid] = mi.encryption_pub_key.value();
          }
          return true;
        });
      return active_members_info;
    }

    MemberId add_member(const MemberPubInfo& member_pub_info)
    {
      auto m = tx.get_view(tables.members);
      auto mc = tx.get_view(tables.member_certs);
      auto md = tx.get_view(tables.member_digests);
      auto v = tx.get_view(tables.values);
      auto ma = tx.get_view(tables.member_acks);
      auto sig = tx.get_view(tables.signatures);

      // The key to a CertDERs table must be a DER, for easy comparison against
      // the DER peer cert retrieved from the connection
      auto member_cert_der =
        tls::make_verifier(member_pub_info.cert)->der_cert_data();

      auto member_id = mc->get(member_cert_der);
      if (member_id.has_value())
      {
        throw std::logic_error(fmt::format(
          "Member certificate already exists (member {})", member_id.value()));
      }

      const auto id = get_next_id(v, ValueIds::NEXT_MEMBER_ID);
      m->put(id, MemberInfo(member_pub_info, MemberStatus::ACCEPTED));
      mc->put(member_cert_der, id);

      crypto::Sha256Hash member_cert_digest(member_pub_info.cert.contents());
      md->put(member_cert_digest.hex_str(), id);

      auto s = sig->get(0);
      if (!s)
      {
        ma->put(id, MemberAck());
      }
      else
      {
        ma->put(id, MemberAck(s->root));
      }
      return id;
    }

    void activate_member(MemberId member_id)
    {
      auto members = tx.get_view(tables.members);
      auto member = members->get(member_id);
      if (!member.has_value())
      {
        throw std::logic_error(fmt::format(
          "Member {} cannot be activated as they do not exist", member_id));
      }

      // Only accepted members can transition to active state
      if (member->status != MemberStatus::ACCEPTED)
      {
        return;
      }

      member->status = MemberStatus::ACTIVE;
      if (
        member->is_recovery() &&
        (get_active_recovery_members().size() >= max_active_recovery_members))
      {
        throw std::logic_error(fmt::format(
          "No more than {} active recovery members are allowed",
          max_active_recovery_members));
      }
      members->put(member_id, member.value());
    }

    bool retire_member(MemberId member_id)
    {
      auto m = tx.get_view(tables.members);
      auto member_to_retire = m->get(member_id);
      if (!member_to_retire.has_value())
      {
        LOG_FAIL_FMT(
          "Could not retire member {}: member does not exist", member_id);
        return false;
      }

      if (member_to_retire->status != MemberStatus::ACTIVE)
      {
        LOG_DEBUG_FMT(
          "Could not retire member {}: member is not active", member_id);
        return true;
      }

      // If the member was active and had a recovery share, check that
      // the new number of active members is still sufficient for
      // recovery
      if (member_to_retire->is_recovery())
      {
        // Because the member to retire is active, there is at least one active
        // member (i.e. get_active_recovery_members_count_after >= 0)
        size_t get_active_recovery_members_count_after =
          get_active_recovery_members().size() - 1;
        auto recovery_threshold = get_recovery_threshold();
        if (get_active_recovery_members_count_after < recovery_threshold)
        {
          LOG_FAIL_FMT(
            "Failed to retire member {}: number of active recovery members "
            "({}) would be less than recovery threshold ({})",
            member_id,
            get_active_recovery_members_count_after,
            recovery_threshold);
          return false;
        }
      }

      member_to_retire->status = MemberStatus::RETIRED;
      m->put(member_id, member_to_retire.value());
      return true;
    }

    std::optional<MemberInfo> get_member_info(MemberId member_id)
    {
      auto m = tx.get_view(tables.members);
      auto member = m->get(member_id);
      if (!member.has_value())
      {
        return {};
      }

      return member.value();
    }

    auto add_user(const ccf::UserInfo& user_info)
    {
      auto u = tx.get_view(tables.users);
      auto uc = tx.get_view(tables.user_certs);
      auto ud = tx.get_view(tables.user_digests);
      auto v = tx.get_view(tables.values);

      auto user_cert_der = tls::make_verifier(user_info.cert)->der_cert_data();

      // Cert should be unique
      auto user_id = uc->get(user_cert_der);
      if (user_id.has_value())
      {
        throw std::logic_error(fmt::format(
          "User certificate already exists (user {})", user_id.value()));
      }

      const auto id = get_next_id(v, ValueIds::NEXT_USER_ID);
      u->put(id, user_info);
      uc->put(user_cert_der, id);

      crypto::Sha256Hash user_cert_digest(user_info.cert.contents());
      ud->put(user_cert_digest.hex_str(), id);
      return id;
    }

    bool remove_user(UserId user_id)
    {
      auto u = tx.get_view(tables.users);
      auto uc = tx.get_view(tables.user_certs);

      auto user_info = u->get(user_id);
      if (!user_info.has_value())
      {
        return false;
      }

      auto pem = tls::Pem(user_info.value().cert);
      auto user_cert_der = tls::make_verifier(pem)->der_cert_data();

      u->remove(user_id);
      uc->remove(user_cert_der);
      return true;
    }

    auto add_node(const NodeInfo& node_info)
    {
      auto node_id =
        get_next_id(tx.get_view(tables.values), ValueIds::NEXT_NODE_ID);

      auto raw_cert = tls::make_verifier(node_info.cert)->der_cert_data();

      auto node_view = tx.get_view(tables.nodes);
      node_view->put(node_id, node_info);
      return node_id;
    }

    auto get_trusted_nodes(std::optional<NodeId> self_to_exclude = std::nullopt)
    {
      // Returns the list of trusted nodes. If self_to_exclude is set,
      // self_to_exclude is not included in the list of returned nodes.
      std::map<NodeId, NodeInfo> active_nodes;

      auto nodes_view = tx.get_view(tables.nodes);

      nodes_view->foreach([&active_nodes, self_to_exclude](
                            const NodeId& nid, const NodeInfo& ni) {
        if (
          ni.status == ccf::NodeStatus::TRUSTED &&
          (!self_to_exclude.has_value() || self_to_exclude.value() != nid))
        {
          active_nodes[nid] = ni;
        }
        return true;
      });

      return active_nodes;
    }

    // Service status should use a state machine, very much like NodeState.
    void create_service(const tls::Pem& network_cert)
    {
      auto service_view = tx.get_view(tables.service);
      service_view->put(0, {network_cert, ServiceStatus::OPENING});
    }

    bool is_service_created()
    {
      auto service_view = tx.get_view(tables.service);
      return service_view->get(0).has_value();
    }

    bool open_service()
    {
      auto service_view = tx.get_view(tables.service);

      auto active_recovery_members_count = get_active_recovery_members().size();
      if (active_recovery_members_count < get_recovery_threshold())
      {
        LOG_FAIL_FMT(
          "Cannot open network as number of active recovery members ({}) is "
          "less than recovery threshold ({})",
          active_recovery_members_count,
          get_recovery_threshold());
        return false;
      }

      auto active_service = service_view->get(0);
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return false;
      }

      if (
        active_service->status != ServiceStatus::OPENING &&
        active_service->status != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        LOG_FAIL_FMT("Could not open current service: status is not OPENING");
        return false;
      }

      active_service->status = ServiceStatus::OPEN;
      service_view->put(0, active_service.value());

      return true;
    }

    std::optional<ServiceStatus> get_service_status()
    {
      auto service_view = tx.get_view(tables.service);
      auto active_service = service_view->get(0);
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return {};
      }

      return active_service->status;
    }

    bool service_wait_for_shares()
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
        LOG_FAIL_FMT(
          "Could not wait for shares on current service: status is not "
          "OPENING");
        return false;
      }

      active_service->status = ServiceStatus::WAITING_FOR_RECOVERY_SHARES;
      service_view->put(0, active_service.value());

      return true;
    }

    void trust_node(NodeId node_id, kv::Version latest_ledger_secret_seqno)
    {
      auto nodes_view = tx.get_view(tables.nodes);
      auto node_info = nodes_view->get(node_id);

      if (!node_info.has_value())
      {
        throw std::logic_error(fmt::format("Node {} does not exist", node_id));
      }

      if (node_info->status == NodeStatus::RETIRED)
      {
        throw std::logic_error(fmt::format("Node {} is retired", node_id));
      }

      node_info->status = NodeStatus::TRUSTED;
      node_info->ledger_secret_seqno = latest_ledger_secret_seqno;
      nodes_view->put(node_id, node_info.value());

      LOG_INFO_FMT("Node {} is now {}", node_id, node_info->status);
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

    void trust_node_code_id(CodeDigest& node_code_id)
    {
      auto codeid_view = tx.get_view(tables.node_code_ids);
      codeid_view->put(node_code_id, CodeStatus::ALLOWED_TO_JOIN);
    }

    void add_key_share_info(const RecoverySharesInfo& key_share_info)
    {
      auto shares_view = tx.get_view(tables.shares);
      shares_view->put(0, key_share_info);
    }

    bool set_recovery_threshold(size_t threshold, bool allow_zero = false)
    {
      auto config_view = tx.get_view(tables.config);

      if (!allow_zero && threshold == 0)
      {
        LOG_FAIL_FMT("Cannot set recovery threshold to 0");
        return false;
      }

      auto service_status = get_service_status();
      if (!service_status.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return false;
      }

      if (service_status.value() == ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        // While waiting for recovery shares, the recovery threshold cannot be
        // modified. Otherwise, the threshold could be passed without triggering
        // the end of recovery procedure
        LOG_FAIL_FMT(
          "Cannot set recovery threshold: service is currently waiting for "
          "recovery shares");
        return false;
      }
      else if (service_status.value() == ServiceStatus::OPEN)
      {
        auto get_active_recovery_members_count =
          get_active_recovery_members().size();
        if (threshold > get_active_recovery_members_count)
        {
          LOG_FAIL_FMT(
            "Cannot set recovery threshold to {} as it is greater than the "
            "number of active recovery members ({})",
            threshold,
            get_active_recovery_members_count);
          return false;
        }
      }

      config_view->put(0, {threshold});
      return true;
    }

    size_t get_recovery_threshold()
    {
      auto config_view = tx.get_view(tables.config);
      auto config = config_view->get(0);
      if (!config.has_value())
      {
        throw std::logic_error(
          "Failed to get recovery threshold: No active configuration found");
      }
      return config->recovery_threshold;
    }
  };
}