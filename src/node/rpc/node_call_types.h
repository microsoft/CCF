// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json_schema.h"
#include "ccf/node_startup_state.h"
#include "ccf/pal/mem.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/service.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "common/configuration.h"
#include "enclave/interface.h"
#include "node/identity.h"
#include "node/ledger_secrets.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct GetState
  {
    using In = void;

    struct Out
    {
      ccf::NodeId node_id;
      ccf::NodeStartupState state;
      kv::Version last_signed_seqno;
      kv::Version startup_seqno;

      // Only on recovery
      std::optional<kv::Version> recovery_target_seqno;
      std::optional<kv::Version> last_recovered_seqno;
    };
  };

  struct GetVersion
  {
    using In = void;

    struct Out
    {
      std::string ccf_version;
      std::string quickjs_version;
      bool unsafe;
    };
  };

  struct CreateNetworkNodeToNode
  {
    struct In
    {
      NodeId node_id;
      crypto::Pem certificate_signing_request;
      crypto::Pem node_endorsed_certificate;
      crypto::Pem public_key;
      crypto::Pem service_cert;
      QuoteInfo quote_info;
      crypto::Pem public_encryption_key;
      CodeDigest code_digest;
      std::optional<HostDataMetadata> snp_security_policy =
        std::nullopt; // base64-encoded
      std::optional<UVMEndorsementsData> snp_uvm_endorsements = std::nullopt;
      NodeInfoNetwork node_info_network;
      nlohmann::json node_data;
      nlohmann::json service_data;
      ccf::TxID create_txid;

      // Only set on genesis transaction, but not on recovery
      std::optional<StartupConfig::Start> genesis_info = std::nullopt;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      NodeInfoNetwork node_info_network;
      QuoteInfo quote_info;
      crypto::Pem public_encryption_key;
      ConsensusType consensus_type = ConsensusType::CFT;
      std::optional<kv::Version> startup_seqno = std::nullopt;
      std::optional<crypto::Pem> certificate_signing_request = std::nullopt;
      nlohmann::json node_data = nullptr;
    };

    struct Out
    {
      NodeStatus node_status;

      // Deprecated in 2.x
      std::optional<NodeId> node_id = std::nullopt;

      struct NetworkInfo
      {
        bool public_only = false;
        kv::Version last_recovered_signed_idx = kv::NoVersion;
        ConsensusType consensus_type = ConsensusType::CFT;
        std::optional<ReconfigurationType> reconfiguration_type = std::nullopt;

        LedgerSecretsMap ledger_secrets;
        NetworkIdentity identity;
        std::optional<ServiceStatus> service_status = std::nullopt;

        std::optional<crypto::Pem> endorsed_certificate = std::nullopt;

        NetworkInfo() {}

        NetworkInfo(
          bool public_only,
          kv::Version last_recovered_signed_idx,
          ConsensusType consensus_type,
          ReconfigurationType reconfiguration_type,
          const LedgerSecretsMap& ledger_secrets,
          const NetworkIdentity& identity,
          ServiceStatus service_status,
          const std::optional<crypto::Pem>& endorsed_certificate) :
          public_only(public_only),
          last_recovered_signed_idx(last_recovered_signed_idx),
          consensus_type(consensus_type),
          reconfiguration_type(reconfiguration_type),
          ledger_secrets(ledger_secrets),
          identity(identity),
          service_status(service_status),
          endorsed_certificate(endorsed_certificate)
        {}

        bool operator==(const NetworkInfo& other) const
        {
          return public_only == other.public_only &&
            last_recovered_signed_idx == other.last_recovered_signed_idx &&
            consensus_type == other.consensus_type &&
            reconfiguration_type == other.reconfiguration_type &&
            ledger_secrets == other.ledger_secrets &&
            identity == other.identity &&
            service_status == other.service_status &&
            endorsed_certificate == other.endorsed_certificate;
        }

        bool operator!=(const NetworkInfo& other) const
        {
          return !(*this == other);
        }
      };

      // Only set if the caller node is trusted
      std::optional<NetworkInfo> network_info = std::nullopt;
    };
  };

  struct MemoryUsage
  {
    using In = void;

    struct Out
    {
      Out(const pal::MallocInfo& info) :
        max_total_heap_size(info.max_total_heap_size),
        current_allocated_heap_size(info.current_allocated_heap_size),
        peak_allocated_heap_size(info.peak_allocated_heap_size)
      {}
      Out() = default;

      size_t max_total_heap_size = 0;
      size_t current_allocated_heap_size = 0;
      size_t peak_allocated_heap_size = 0;
    };
  };
}
