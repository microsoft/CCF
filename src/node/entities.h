// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <limits>
#include <map>
#include <stdint.h>
#include <vector>

namespace ccf
{
  using ObjectId = uint64_t;

  constexpr ObjectId INVALID_ID = (std::numeric_limits<ObjectId>::max)();

  using NodeId = uint64_t;
  using Index = int64_t;
  using Node2NodeMsg = uint64_t;

  using MemberId = ObjectId;
  using UserId = ObjectId;
  using CallerId = ObjectId;
  using Cert = std::vector<uint8_t>;

  // SGX MRENCLAVE is SHA256 digest
  static constexpr size_t CODE_DIGEST_BYTES = 256 / 8;
  using CodeDigest = std::array<uint8_t, CODE_DIGEST_BYTES>;

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

    // Member identities
    static constexpr auto MEMBERS = "public:ccf.gov.members.info";
    static constexpr auto MEMBER_ACKS = "public:ccf.gov.members.acks";
    static constexpr auto MEMBER_CERT_DERS =
      "public:ccf.internal.members.certs_der";
    static constexpr auto MEMBER_DIGESTS =
      "public:ccf.internal.members.digests";

    // User identities
    static constexpr auto USERS = "public:ccf.gov.users.info";
    static constexpr auto USER_CERT_DERS =
      "public:ccf.internal.users.certs_der";
    static constexpr auto USER_DIGESTS = "public:ccf.internal.users.digests";

    // Nodes identities and allowed code ids
    static constexpr auto NODES = "public:ccf.gov.nodes.info";
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";

    // Service information
    static constexpr auto SERVICE = "public:ccf.gov.service.info";
    static constexpr auto CONFIGURATION = "public:ccf.gov.service.config";

    // Governance
    static constexpr auto PROPOSALS = "public:ccf.gov.proposals";
    static constexpr auto GOV_SCRIPTS = "public:ccf.gov.scripts";
    static constexpr auto GOV_HISTORY = "public:ccf.gov.history";
    static constexpr auto WHITELISTS = "public:ccf.gov.whitelists";

    // JS applications, not service specific but writable by governance only
    static constexpr auto APP_SCRIPTS = "public:gov.scripts";
    static constexpr auto MODULES = "public:gov.modules";
    static constexpr auto ENDPOINTS = "public:gov.endpoints";
    static constexpr auto SERVICE_PRINCIPALS = "public:gov.service_principals";

    // JWT issuers
    static constexpr auto CA_CERT_DERS = "public:ccf.gov.jwt.ca_certs_der";
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
    static constexpr auto VALUES = "public:ccf.internal.values";

    // Consensus
    static constexpr auto AFT_REQUESTS =
      "public:ccf.internal.consensus.requests";
    static constexpr auto NEW_VIEWS = "public:ccf.internal.consensus.new_views";
    static constexpr auto BACKUP_SIGNATURES =
      "public:ccf.internal.consensus.backup_signatures";
    static constexpr auto NONCES = "public:ccf.internal.consensus.nonces";
  };

}

namespace enclave
{
  enum FrameFormat : uint8_t
  {
    http = 0,
    ws
  };
}
