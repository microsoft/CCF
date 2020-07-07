// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"
#include "node/identity.h"
#include "node/ledger_secrets.h"
#include "node/members.h"
#include "node/network_encryption.h"
#include "node/node_info_network.h"

#include <nlohmann/json.hpp>

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
    readingPrivateLedger
  };

  struct GetSignedIndex
  {
    using In = void;

    enum class State
    {
      ReadingPublicLedger,
      ReadingPrivateLedger,
      PartOfNetwork,
      PartOfPublicNetwork,
    };

    struct Out
    {
      State state;
      kv::Version signed_index;
    };
  };

  struct GetState
  {
    using In = void;

    struct Out
    {
      ccf::State state;
      kv::Version last_signed_index;
    };
  };

  struct GetQuotes
  {
    using In = void;

    struct Quote
    {
      NodeId node_id = {};
      std::string raw = {}; // < Hex-encoded

      std::string error = {};
      std::string mrenclave = {}; // < Hex-encoded
    };

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  struct CreateNetworkNodeToNode
  {
    struct In
    {
      std::vector<MemberPubInfo> members_info;
      std::string gov_script;
      tls::Pem node_cert;
      tls::Pem network_cert;
      std::vector<uint8_t> quote;
      tls::Pem public_encryption_key;
      std::vector<uint8_t> code_digest;
      NodeInfoNetwork node_info_network;
      ConsensusType consensus_type = ConsensusType::RAFT;
      size_t recovery_threshold;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      NodeInfoNetwork node_info_network;
      std::vector<uint8_t> quote;
      tls::Pem public_encryption_key;
      ConsensusType consensus_type = ConsensusType::RAFT;
    };

    struct Out
    {
      NodeStatus node_status;
      NodeId node_id;
      bool public_only;
      kv::Version last_recovered_commit_idx;
      ConsensusType consensus_type = ConsensusType::RAFT;

      struct NetworkInfo
      {
        LedgerSecrets ledger_secrets;
        NetworkIdentity identity;
        NetworkEncryptionKey encryption_key;

        bool operator==(const NetworkInfo& other) const
        {
          return ledger_secrets == other.ledger_secrets &&
            identity == other.identity &&
            encryption_key == other.encryption_key;
        }

        bool operator!=(const NetworkInfo& other) const
        {
          return !(*this == other);
        }
      };
      NetworkInfo network_info;
    };
  };
}

// Used by fmtlib to render ccf::State
namespace std
{
  std::ostream& operator<<(std::ostream& os, ccf::State s)
  {
    switch (s)
    {
      case ccf::State::uninitialized:
        return os << "uninitialized";
      case ccf::State::initialized:
        return os << "initialized";
      case ccf::State::pending:
        return os << "pending";
      case ccf::State::partOfPublicNetwork:
        return os << "partOfPublicNetwork";
      case ccf::State::partOfNetwork:
        return os << "partOfNetwork";
      case ccf::State::readingPublicLedger:
        return os << "readingPublicLedger";
      case ccf::State::readingPrivateLedger:
        return os << "readingPrivateLedger";
      default:
        return os << "unknown value";
    }
  }
}