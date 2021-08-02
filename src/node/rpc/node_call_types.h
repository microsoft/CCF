// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"
#include "node/config.h"
#include "node/identity.h"
#include "node/ledger_secrets.h"
#include "node/members.h"
#include "node/node_info_network.h"
#include "tls/base64.h"

#include <nlohmann/json.hpp>
#include <openenclave/advanced/mallinfo.h>

namespace ccf
{
  enum class State
  {
    uninitialized,
    initialized,
    pending,
    partOfPublicNetwork,
    partOfNetwork,
    readingPublicLedger,
    readingPrivateLedger,
    verifyingSnapshot
  };

  struct GetState
  {
    using In = void;

    struct Out
    {
      ccf::NodeId node_id;
      ccf::State state;
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
    };
  };

  struct CreateNetworkNodeToNode
  {
    struct In
    {
      std::vector<NewMember> members_info;
      std::string constitution;
      NodeId node_id;
      crypto::Pem node_cert;
      crypto::Pem network_cert;
      QuoteInfo quote_info;
      crypto::Pem public_encryption_key;
      CodeDigest code_digest;
      NodeInfoNetwork node_info_network;
      ServiceConfiguration configuration;
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
    };

    struct Out
    {
      NodeStatus node_status;
      NodeId node_id; // Only used in BFT

      // Only if the caller node is trusted
      struct NetworkInfo
      {
        bool public_only = false;
        kv::Version last_recovered_signed_idx = kv::NoVersion;
        ConsensusType consensus_type = ConsensusType::CFT;

        LedgerSecretsMap ledger_secrets;
        NetworkIdentity identity;

        bool operator==(const NetworkInfo& other) const
        {
          return public_only == other.public_only &&
            last_recovered_signed_idx == other.last_recovered_signed_idx &&
            consensus_type == other.consensus_type &&
            ledger_secrets == other.ledger_secrets &&
            identity == other.identity;
        }

        bool operator!=(const NetworkInfo& other) const
        {
          return !(*this == other);
        }
      };

      NetworkInfo network_info;
    };
  };

  struct MemoryUsage
  {
    using In = void;

    struct Out
    {
      Out(const oe_mallinfo_t& info) :
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