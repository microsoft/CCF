// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"

#include <limits>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

namespace ccf
{
  using Node2NodeMsg = uint64_t;

  using Cert = std::vector<uint8_t>;

  enum class ActorsType : uint64_t
  {
    members = 0,
    users,
    nodes,
    // not to be used
    unknown
  };

  constexpr auto get_actor_prefix(ActorsType at)
  {
    switch (at)
    {
      case ActorsType::members:
      {
        return "gov";
      }
      case ActorsType::users:
      {
        return "app";
      }
      case ActorsType::nodes:
      {
        return "node";
      }
      default:
      {
        return "";
      }
    }
  }

  struct Tables
  {
    // Service tables

    // Members
    static constexpr auto MEMBER_CERTS = "public:ccf.gov.members.certs";
    static constexpr auto MEMBER_ENCRYPTION_PUBLIC_KEYS =
      "public:ccf.gov.members.encryption_public_keys";
    static constexpr auto MEMBER_INFO = "public:ccf.gov.members.info";
    static constexpr auto MEMBER_ACKS = "public:ccf.gov.members.acks";

    // Users
    static constexpr auto USER_CERTS = "public:ccf.gov.users.certs";
    static constexpr auto USER_INFO = "public:ccf.gov.users.info";

    // Nodes identities and allowed code ids
    static constexpr auto NODES = "public:ccf.gov.nodes.info";
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
    static constexpr auto NODES_CONFIGURATIONS =
      "public:ccf.gov.nodes.network.configurations";

    // Service information
    static constexpr auto SERVICE = "public:ccf.gov.service.info";
    static constexpr auto CONFIGURATION = "public:ccf.gov.service.config";

    // JS applications, not service specific but writable by governance only
    static constexpr auto MODULES = "public:ccf.gov.modules";
    static constexpr auto MODULES_QUICKJS_BYTECODE =
      "public:ccf.gov.modules_quickjs_bytecode";
    static constexpr auto MODULES_QUICKJS_VERSION =
      "public:ccf.gov.modules_quickjs_version";
    static constexpr auto ENDPOINTS = "public:ccf.gov.endpoints";

    // TLS
    static constexpr auto CA_CERT_BUNDLE_PEMS =
      "public:ccf.gov.tls.ca_cert_bundles";

    // JWT issuers
    static constexpr auto JWT_ISSUERS = "public:ccf.gov.jwt.issuers";
    static constexpr auto JWT_PUBLIC_SIGNING_KEYS =
      "public:ccf.gov.jwt.public_signing_keys";
    static constexpr auto JWT_PUBLIC_SIGNING_KEY_ISSUER =
      "public:ccf.gov.jwt.public_signing_key_issuer";

    // Internal only
    static constexpr auto ENCRYPTED_PAST_LEDGER_SECRET =
      "public:ccf.internal.historical_encrypted_ledger_secret";
    static constexpr auto ENCRYPTED_LEDGER_SECRETS =
      "public:ccf.internal.encrypted_ledger_secrets";
    static constexpr auto SHARES = "public:ccf.internal.recovery_shares";
    static constexpr auto SUBMITTED_SHARES =
      "public:ccf.internal.encrypted_submitted_shares";
    static constexpr auto SNAPSHOT_EVIDENCE =
      "public:ccf.internal.snapshot_evidence";
    static constexpr auto SIGNATURES = "public:ccf.internal.signatures";
    static constexpr auto SERIALISED_MERKLE_TREE = "public:ccf.internal.tree";
    static constexpr auto VALUES = "public:ccf.internal.values";

    // Consensus
    static constexpr auto AFT_REQUESTS = "ccf.internal.consensus.requests";
    static constexpr auto NEW_VIEWS = "public:ccf.internal.consensus.new_views";
    static constexpr auto BACKUP_SIGNATURES =
      "public:ccf.internal.consensus.backup_signatures";
    static constexpr auto NONCES = "public:ccf.internal.consensus.nonces";

    // Governance
    static constexpr auto GOV_HISTORY = "public:ccf.gov.history";
    static constexpr auto CONSTITUTION = "public:ccf.gov.constitution";
    static constexpr auto PROPOSALS = "public:ccf.gov.proposals";
    static constexpr auto PROPOSALS_INFO = "public:ccf.gov.proposals_info";

    // Byzantine network identities
    static constexpr auto BYZANTINE_NETWORK_IDENTITIES =
      "public:ccf.internal.byzantine_network_identities";
  };

}

namespace enclave
{
  enum FrameFormat : uint8_t
  {
    http = 0
  };
}
