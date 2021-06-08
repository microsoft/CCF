// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/tx.h"
#include "code_id.h"
#include "crypto/hash.h"
#include "crypto/verifier.h"
#include "entities.h"
#include "ledger_secrets.h"
#include "members.h"
#include "network_tables.h"
#include "node_info_network.h"
#include "nodes.h"
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

  public:
    GenesisGenerator(NetworkTables& tables_, kv::Tx& tx_) :
      tables(tables_),
      tx(tx_)
    {}

    void init_values()
    {
      auto v = tx.rw(tables.values);
      for (int id_type = 0; id_type < ValueIds::END_ID; id_type++)
      {
        v->put(id_type, 0);
      }
    }

    void retire_active_nodes()
    {
      auto nodes = tx.rw(tables.nodes);

      std::map<NodeId, NodeInfo> nodes_to_delete;
      nodes->foreach([&nodes_to_delete](const NodeId& nid, const NodeInfo& ni) {
        // Only retire nodes that have not already been retired
        if (ni.status != NodeStatus::RETIRED)
          nodes_to_delete[nid] = ni;
        return true;
      });

      for (auto [nid, ni] : nodes_to_delete)
      {
        ni.status = NodeStatus::RETIRED;
        nodes->put(nid, ni);
      }
    }

    bool is_recovery_member(const MemberId& member_id)
    {
      auto member_encryption_public_keys =
        tx.ro(tables.member_encryption_public_keys);

      return member_encryption_public_keys->get(member_id).has_value();
    }

    bool is_active_member(const MemberId& member_id)
    {
      auto member_info = tx.ro(tables.member_info);
      auto mi = member_info->get(member_id);
      if (!mi.has_value())
      {
        return false;
      }

      return mi->status == MemberStatus::ACTIVE;
    }

    std::map<MemberId, crypto::Pem> get_active_recovery_members()
    {
      auto member_info = tx.ro(tables.member_info);
      auto member_encryption_public_keys =
        tx.ro(tables.member_encryption_public_keys);

      std::map<MemberId, crypto::Pem> active_recovery_members;

      member_encryption_public_keys->foreach(
        [&active_recovery_members,
         &member_info](const auto& mid, const auto& pem) {
          auto info = member_info->get(mid);
          if (!info.has_value())
          {
            throw std::logic_error(
              fmt::format("Recovery member {} has no member info", mid));
          }

          if (info->status == MemberStatus::ACTIVE)
          {
            active_recovery_members[mid] = pem;
          }
          return true;
        });
      return active_recovery_members;
    }

    MemberId add_member(const NewMember& member_pub_info)
    {
      auto member_certs = tx.rw(tables.member_certs);
      auto member_info = tx.rw(tables.member_info);
      auto member_acks = tx.rw(tables.member_acks);
      auto signatures = tx.ro(tables.signatures);

      auto member_cert_der =
        crypto::make_verifier(member_pub_info.cert)->cert_der();
      auto id = crypto::Sha256Hash(member_cert_der).hex_str();

      auto member = member_certs->get(id);
      if (member.has_value())
      {
        // No effect if member already exists
        return id;
      }

      member_certs->put(id, member_pub_info.cert);
      member_info->put(
        id, {MemberStatus::ACCEPTED, member_pub_info.member_data});

      if (member_pub_info.encryption_pub_key.has_value())
      {
        auto member_encryption_public_keys =
          tx.rw(tables.member_encryption_public_keys);
        member_encryption_public_keys->put(
          id, member_pub_info.encryption_pub_key.value());
      }

      auto s = signatures->get();
      if (!s)
      {
        member_acks->put(id, MemberAck());
      }
      else
      {
        member_acks->put(id, MemberAck(s->root));
      }
      return id;
    }

    void activate_member(const MemberId& member_id)
    {
      auto member_info = tx.rw(tables.member_info);

      auto member = member_info->get(member_id);
      if (!member.has_value())
      {
        throw std::logic_error(fmt::format(
          "Member {} cannot be activated as they do not exist", member_id));
      }

      member->status = MemberStatus::ACTIVE;
      if (
        is_recovery_member(member_id) &&
        (get_active_recovery_members().size() >= max_active_recovery_members))
      {
        throw std::logic_error(fmt::format(
          "Cannot activate new recovery member {}: no more than {} active "
          "recovery members are allowed",
          member_id,
          max_active_recovery_members));
      }
      member_info->put(member_id, member.value());
    }

    bool remove_member(const MemberId& member_id)
    {
      auto member_certs = tx.rw(tables.member_certs);
      auto member_encryption_public_keys =
        tx.rw(tables.member_encryption_public_keys);
      auto member_info = tx.rw(tables.member_info);
      auto member_acks = tx.rw(tables.member_acks);
      auto member_gov_history = tx.rw(tables.governance_history);

      auto member_to_remove = member_info->get(member_id);
      if (!member_to_remove.has_value())
      {
        // The remove member proposal is idempotent so if the member does not
        // exist, the proposal should succeed with no effect
        LOG_FAIL_FMT(
          "Could not remove member {}: member does not exist", member_id);
        return true;
      }

      // If the member was active and had a recovery share, check that
      // the new number of active members is still sufficient for
      // recovery
      if (
        member_to_remove->status == MemberStatus::ACTIVE &&
        is_recovery_member(member_id))
      {
        // Because the member to remove is active, there is at least one
        // active member (i.e. get_active_recovery_members_count_after >= 0)
        size_t get_active_recovery_members_count_after =
          get_active_recovery_members().size() - 1;
        auto recovery_threshold = get_recovery_threshold();
        if (get_active_recovery_members_count_after < recovery_threshold)
        {
          LOG_FAIL_FMT(
            "Failed to remove recovery member {}: number of active recovery "
            "members ({}) would be less than recovery threshold ({})",
            member_id,
            get_active_recovery_members_count_after,
            recovery_threshold);
          return false;
        }
      }

      member_info->remove(member_id);
      member_encryption_public_keys->remove(member_id);
      member_certs->remove(member_id);
      member_acks->remove(member_id);
      member_gov_history->remove(member_id);

      return true;
    }

    UserId add_user(const NewUser& new_user)
    {
      auto user_certs = tx.rw(tables.user_certs);

      auto user_cert_der = crypto::make_verifier(new_user.cert)->cert_der();
      auto id = crypto::Sha256Hash(user_cert_der).hex_str();

      auto user_cert = user_certs->get(id);
      if (user_cert.has_value())
      {
        throw std::logic_error(
          fmt::format("Certificate already exists for user {}", id));
      }

      user_certs->put(id, new_user.cert);

      if (new_user.user_data != nullptr)
      {
        auto user_info = tx.rw(tables.user_info);
        auto ui = user_info->get(id);
        if (ui.has_value())
        {
          throw std::logic_error(
            fmt::format("User data already exists for user {}", id));
        }

        user_info->put(id, {new_user.user_data});
      }

      return id;
    }

    void remove_user(const UserId& user_id)
    {
      // Has no effect if the user does not exist
      auto user_certs = tx.rw(tables.user_certs);
      auto user_info = tx.rw(tables.user_info);

      user_certs->remove(user_id);
      user_info->remove(user_id);
    }

    void add_node(const NodeId& id, const NodeInfo& node_info)
    {
      auto config = tx.ro(tables.config);
      auto c0 = config->get();
      if (c0 && c0->consensus == BFT)
      {
        // Increment the node id (only used in BFT)
        get_next_id(tx.rw(tables.values), ValueIds::NEXT_NODE_ID);
      }

      auto node = tx.rw(tables.nodes);
      node->put(id, node_info);
    }

    auto get_trusted_nodes(std::optional<NodeId> self_to_exclude = std::nullopt)
    {
      // Returns the list of trusted nodes. If self_to_exclude is set,
      // self_to_exclude is not included in the list of returned nodes.
      std::map<NodeId, NodeInfo> active_nodes;

      auto nodes = tx.ro(tables.nodes);

      nodes->foreach([&active_nodes,
                      self_to_exclude](const NodeId& nid, const NodeInfo& ni) {
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
    void create_service(const crypto::Pem& network_cert)
    {
      auto service = tx.rw(tables.service);
      service->put({network_cert, ServiceStatus::OPENING});
    }

    bool is_service_created()
    {
      auto service = tx.ro(tables.service);
      return service->get().has_value();
    }

    bool open_service()
    {
      auto service = tx.rw(tables.service);

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

      auto active_service = service->get();
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return false;
      }

      if (active_service->status == ServiceStatus::OPEN)
      {
        // If the service is already open, return with no effect
        return true;
      }

      if (
        active_service->status != ServiceStatus::OPENING &&
        active_service->status != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        LOG_FAIL_FMT("Could not open current service: status is not OPENING");
        return false;
      }

      active_service->status = ServiceStatus::OPEN;
      service->put(active_service.value());

      return true;
    }

    std::optional<ServiceStatus> get_service_status()
    {
      auto service = tx.ro(tables.service);
      auto active_service = service->get();
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return {};
      }

      return active_service->status;
    }

    void trust_node(
      const NodeId& node_id,
      kv::Version latest_ledger_secret_seqno,
      bool caught_up = false)
    {
      auto nodes = tx.rw(tables.nodes);
      auto node_info = nodes->get(node_id);

      if (!node_info.has_value())
      {
        throw std::logic_error(fmt::format("Node {} does not exist", node_id));
      }

      if (node_info->status == NodeStatus::RETIRED)
      {
        throw std::logic_error(fmt::format("Node {} is retired", node_id));
      }

      node_info->status =
        caught_up ? NodeStatus::TRUSTED : NodeStatus::CATCHING_UP;
      node_info->ledger_secret_seqno = latest_ledger_secret_seqno;
      nodes->put(node_id, node_info.value());

      LOG_INFO_FMT("Node {} is now {}", node_id, node_info->status);
    }

    auto get_last_signature()
    {
      auto signatures = tx.ro(tables.signatures);
      return signatures->get();
    }

    void set_constitution(const std::string& constitution)
    {
      tx.rw(tables.constitution)->put(0, constitution);
    }

    void trust_node_code_id(const CodeDigest& node_code_id)
    {
      auto codeid = tx.rw(tables.node_code_ids);
      codeid->put(node_code_id, CodeStatus::ALLOWED_TO_JOIN);
    }

    void init_configuration(const ServiceConfiguration& configuration)
    {
      auto config = tx.rw(tables.config);
      if (config->has())
      {
        throw std::logic_error(
          "Cannot initialise service configuration: configuration already "
          "exists");
      }

      config->put(configuration);
    }

    bool set_recovery_threshold(size_t threshold)
    {
      auto config = tx.rw(tables.config);

      if (threshold == 0)
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
        // modified. Otherwise, the threshold could be passed without
        // triggering the end of recovery procedure
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

      auto current_config = config->get();
      if (!current_config.has_value())
      {
        throw std::logic_error("Configuration should already be set");
      }

      current_config->recovery_threshold = threshold;
      config->put(current_config.value());
      return true;
    }

    size_t get_recovery_threshold()
    {
      auto config = tx.ro(tables.config);
      auto current_config = config->get();
      if (!current_config.has_value())
      {
        throw std::logic_error(
          "Failed to get recovery threshold: No active configuration found");
      }
      return current_config->recovery_threshold;
    }
  };
}
