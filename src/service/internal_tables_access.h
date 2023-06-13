// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/tx.h"
#include "node/ledger_secrets.h"
#include "node/uvm_endorsements.h"
#include "service/tables/previous_service_identity.h"

#include <algorithm>
#include <ostream>

namespace ccf
{
  // This class provides functions for interacting with various internal
  // service-governance tables. Specifically, it aims to maintain some
  // invariants amongst these tables (eg - keys being present in multiple
  // tables) despite access by distinct callers. These tables may be accessed
  // directly with a Tx object, but it is recommended to use these methods where
  // available.
  class InternalTablesAccess
  {
  public:
    // This class is purely a container for static methods, should not be
    // instantiated
    InternalTablesAccess() = delete;

    static void retire_active_nodes(kv::Tx& tx)
    {
      auto nodes = tx.rw<ccf::Nodes>(Tables::NODES);

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

    static bool is_recovery_member(
      kv::ReadOnlyTx& tx, const MemberId& member_id)
    {
      auto member_encryption_public_keys =
        tx.ro<ccf::MemberPublicEncryptionKeys>(
          Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

      return member_encryption_public_keys->get(member_id).has_value();
    }

    static bool is_active_member(kv::ReadOnlyTx& tx, const MemberId& member_id)
    {
      auto member_info = tx.ro<ccf::MemberInfo>(Tables::MEMBER_INFO);
      auto mi = member_info->get(member_id);
      if (!mi.has_value())
      {
        return false;
      }

      return mi->status == MemberStatus::ACTIVE;
    }

    static std::map<MemberId, crypto::Pem> get_active_recovery_members(
      kv::ReadOnlyTx& tx)
    {
      auto member_info = tx.ro<ccf::MemberInfo>(Tables::MEMBER_INFO);
      auto member_encryption_public_keys =
        tx.ro<ccf::MemberPublicEncryptionKeys>(
          Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

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

    static MemberId add_member(kv::Tx& tx, const NewMember& member_pub_info)
    {
      auto member_certs = tx.rw<ccf::MemberCerts>(Tables::MEMBER_CERTS);
      auto member_info = tx.rw<ccf::MemberInfo>(Tables::MEMBER_INFO);
      auto member_acks = tx.rw<ccf::MemberAcks>(Tables::MEMBER_ACKS);
      auto signatures = tx.ro<ccf::Signatures>(Tables::SIGNATURES);

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
          tx.rw<ccf::MemberPublicEncryptionKeys>(
            Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);
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

    static void activate_member(kv::Tx& tx, const MemberId& member_id)
    {
      auto member_info = tx.rw<ccf::MemberInfo>(Tables::MEMBER_INFO);

      auto member = member_info->get(member_id);
      if (!member.has_value())
      {
        throw std::logic_error(fmt::format(
          "Member {} cannot be activated as they do not exist", member_id));
      }

      member->status = MemberStatus::ACTIVE;
      if (
        is_recovery_member(tx, member_id) &&
        (get_active_recovery_members(tx).size() >= max_active_recovery_members))
      {
        throw std::logic_error(fmt::format(
          "Cannot activate new recovery member {}: no more than {} active "
          "recovery members are allowed",
          member_id,
          max_active_recovery_members));
      }
      member_info->put(member_id, member.value());
    }

    static bool remove_member(kv::Tx& tx, const MemberId& member_id)
    {
      auto member_certs = tx.rw<ccf::MemberCerts>(Tables::MEMBER_CERTS);
      auto member_encryption_public_keys =
        tx.rw<ccf::MemberPublicEncryptionKeys>(
          Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);
      auto member_info = tx.rw<ccf::MemberInfo>(Tables::MEMBER_INFO);
      auto member_acks = tx.rw<ccf::MemberAcks>(Tables::MEMBER_ACKS);
      auto member_gov_history =
        tx.rw<ccf::GovernanceHistory>(Tables::GOV_HISTORY);

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
        is_recovery_member(tx, member_id))
      {
        // Because the member to remove is active, there is at least one active
        // member (i.e. get_active_recovery_members_count_after >= 0)
        size_t get_active_recovery_members_count_after =
          get_active_recovery_members(tx).size() - 1;
        auto recovery_threshold = get_recovery_threshold(tx);
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

    static UserId add_user(kv::Tx& tx, const NewUser& new_user)
    {
      auto user_certs = tx.rw<ccf::UserCerts>(Tables::USER_CERTS);

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
        auto user_info = tx.rw<ccf::UserInfo>(Tables::USER_INFO);
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

    static void remove_user(kv::Tx& tx, const UserId& user_id)
    {
      // Has no effect if the user does not exist
      auto user_certs = tx.rw<ccf::UserCerts>(Tables::USER_CERTS);
      auto user_info = tx.rw<ccf::UserInfo>(Tables::USER_INFO);

      user_certs->remove(user_id);
      user_info->remove(user_id);
    }

    static void add_node(
      kv::Tx& tx, const NodeId& id, const NodeInfo& node_info)
    {
      auto node = tx.rw<ccf::Nodes>(Tables::NODES);
      node->put(id, node_info);
    }

    static auto get_trusted_nodes(
      kv::ReadOnlyTx& tx, std::optional<NodeId> self_to_exclude = std::nullopt)
    {
      // Returns the list of trusted nodes. If self_to_exclude is set,
      // self_to_exclude is not included in the list of returned nodes.
      std::map<NodeId, NodeInfo> active_nodes;

      auto nodes = tx.ro<ccf::Nodes>(Tables::NODES);

      nodes->foreach([&active_nodes,
                      self_to_exclude](const NodeId& nid, const NodeInfo& ni) {
        if (
          (ni.status == ccf::NodeStatus::TRUSTED) &&
          (!self_to_exclude.has_value() || self_to_exclude.value() != nid))
        {
          active_nodes[nid] = ni;
        }
        return true;
      });

      return active_nodes;
    }

    // Service status should use a state machine, very much like NodeState.
    static void create_service(
      kv::Tx& tx,
      const crypto::Pem& service_cert,
      ccf::TxID create_txid,
      nlohmann::json service_data = nullptr,
      bool recovering = false)
    {
      auto service = tx.rw<ccf::Service>(Tables::SERVICE);

      size_t recovery_count = 0;

      if (service->has())
      {
        const auto prev_service_info = service->get();
        auto previous_service_identity = tx.wo<ccf::PreviousServiceIdentity>(
          ccf::Tables::PREVIOUS_SERVICE_IDENTITY);
        previous_service_identity->put(prev_service_info->cert);

        // Record number of recoveries for service. If the value does
        // not exist in the table (i.e. pre 2.x ledger), assume it is the first
        // recovery.
        recovery_count = prev_service_info->recovery_count.value_or(0) + 1;
      }

      service->put(
        {service_cert,
         recovering ? ServiceStatus::RECOVERING : ServiceStatus::OPENING,
         recovering ? service->get_version_of_previous_write() : std::nullopt,
         recovery_count,
         service_data,
         create_txid});
    }

    static bool is_service_created(
      kv::ReadOnlyTx& tx, const crypto::Pem& expected_service_cert)
    {
      auto service = tx.ro<ccf::Service>(Tables::SERVICE)->get();
      return service.has_value() && service->cert == expected_service_cert;
    }

    static bool open_service(kv::Tx& tx)
    {
      auto service = tx.rw<ccf::Service>(Tables::SERVICE);

      auto active_recovery_members_count =
        get_active_recovery_members(tx).size();
      if (active_recovery_members_count < get_recovery_threshold(tx))
      {
        LOG_FAIL_FMT(
          "Cannot open network as number of active recovery members ({}) is "
          "less than recovery threshold ({})",
          active_recovery_members_count,
          get_recovery_threshold(tx));
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
        LOG_FAIL_FMT(
          "Could not open current service: status is not OPENING or "
          "WAITING_FOR_RECOVERY_SHARES");
        return false;
      }

      active_service->status = ServiceStatus::OPEN;
      active_service->previous_service_identity_version =
        service->get_version_of_previous_write();
      service->put(active_service.value());

      return true;
    }

    static std::optional<ServiceStatus> get_service_status(kv::ReadOnlyTx& tx)
    {
      auto service = tx.ro<ccf::Service>(Tables::SERVICE);
      auto active_service = service->get();
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return {};
      }

      return active_service->status;
    }

    static void trust_node(
      kv::Tx& tx, const NodeId& node_id, kv::Version latest_ledger_secret_seqno)
    {
      auto nodes = tx.rw<ccf::Nodes>(Tables::NODES);
      auto node_info = nodes->get(node_id);

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
      nodes->put(node_id, node_info.value());

      LOG_INFO_FMT("Node {} is now {}", node_id, node_info->status);
    }

    static void set_constitution(kv::Tx& tx, const std::string& constitution)
    {
      tx.rw<ccf::Constitution>(Tables::CONSTITUTION)->put(constitution);
    }

    static void trust_node_measurement(
      kv::Tx& tx,
      const pal::PlatformAttestationMeasurement& node_measurement,
      const QuoteFormat& platform)
    {
      switch (platform)
      {
        // For now, record null code id for virtual platform in SGX code id
        // table
        case QuoteFormat::insecure_virtual:
        case QuoteFormat::oe_sgx_v1:
        {
          tx.rw<CodeIDs>(Tables::NODE_CODE_IDS)
            ->put(
              pal::SgxAttestationMeasurement(node_measurement),
              CodeStatus::ALLOWED_TO_JOIN);
          break;
        }
        case QuoteFormat::amd_sev_snp_v1:
        {
          tx.rw<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)
            ->put(
              pal::SnpAttestationMeasurement(node_measurement),
              CodeStatus::ALLOWED_TO_JOIN);
          break;
        }
        default:
        {
          throw std::logic_error(fmt::format(
            "Unexpected quote format {} when trusting node code id", platform));
        }
      }
    }

    static void trust_node_host_data(
      kv::Tx& tx,
      const HostData& host_data,
      const std::optional<HostDataMetadata>& security_policy = std::nullopt)
    {
      auto host_data_table = tx.rw<ccf::SnpHostDataMap>(Tables::HOST_DATA);
      if (security_policy.has_value())
      {
        auto raw_security_policy =
          crypto::raw_from_b64(security_policy.value());
        host_data_table->put(
          host_data, {raw_security_policy.begin(), raw_security_policy.end()});
      }
      else
      {
        LOG_TRACE_FMT("Trusting node with unset policy");
        host_data_table->put(host_data, pal::snp::NO_SECURITY_POLICY);
      }
    }

    static void trust_node_uvm_endorsements(
      kv::Tx& tx, const std::optional<UVMEndorsements>& uvm_endorsements)
    {
      if (!uvm_endorsements.has_value())
      {
        // UVM endorsements are optional
        return;
      }

      auto uvme =
        tx.rw<ccf::SNPUVMEndorsements>(Tables::NODE_SNP_UVM_ENDORSEMENTS);
      uvme->put(
        uvm_endorsements->did,
        {{uvm_endorsements->feed, {uvm_endorsements->svn}}});
    }

    static void init_configuration(
      kv::Tx& tx, const ServiceConfiguration& configuration)
    {
      auto config = tx.rw<ccf::Configuration>(Tables::CONFIGURATION);
      if (config->has())
      {
        throw std::logic_error(
          "Cannot initialise service configuration: configuration already "
          "exists");
      }

      config->put(configuration);
    }

    static bool set_recovery_threshold(kv::Tx& tx, size_t threshold)
    {
      auto config = tx.rw<ccf::Configuration>(Tables::CONFIGURATION);

      if (threshold == 0)
      {
        LOG_FAIL_FMT("Cannot set recovery threshold to 0");
        return false;
      }

      auto service_status = get_service_status(tx);
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
          get_active_recovery_members(tx).size();
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

    static size_t get_recovery_threshold(kv::ReadOnlyTx& tx)
    {
      auto config = tx.ro<ccf::Configuration>(Tables::CONFIGURATION);
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
