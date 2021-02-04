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
    static constexpr auto MEMBERS = "public:ccf.gov.members";
    static constexpr auto MEMBER_ACKS = "public:ccf.gov.members.acks";
    static constexpr auto MEMBER_CERT_DERS =
      "public:ccf.internal.members.certs_der";
    static constexpr auto MEMBER_DIGESTS =
      "public:ccf.internal.members.digests";

    // User identities
    static constexpr auto USERS = "public:ccf.gov.users";
    static constexpr auto USER_CERT_DERS =
      "public:ccf.internal.users.certs_der";
    static constexpr auto USER_DIGESTS = "public:internal.gov.users.digests";
    static constexpr auto SERVICE_PRINCIPALS =
      "public:ccf.gov.service_principals";

    // Nodes identities and allowed code ids
    static constexpr auto NODES = "public:ccf.gov.nodes";
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";

    // Service information
    static constexpr auto SERVICE = "public:ccf.gov.service";
    static constexpr auto CONFIGURATION = "public:ccf.gov.service.config";
    static constexpr auto VALUES = "public:ccf.internal.values";

    // Governance
    static constexpr auto PROPOSALS = "public:ccf.gov.proposals";
    static constexpr auto GOV_SCRIPTS = "public:ccf.gov.governance.scripts";
    static constexpr auto GOV_HISTORY = "public:ccf.gov.governance.history";
    static constexpr auto WHITELISTS = "public:ccf.gov.whitelists";

    // JS applications
    static constexpr auto APP_SCRIPTS = "public:ccf.app.scripts";
    static constexpr auto MODULES = "public:ccf.app.modules";
    static constexpr auto ENDPOINTS = "public:ccf.app.endpoints";

    // JWT issuers
    static constexpr auto CA_CERT_DERS = "public:ccf.gov.jwt.ca_certs_der";
    static constexpr auto JWT_ISSUERS = "public:ccf.gov.jwt.issuers";
    static constexpr auto JWT_PUBLIC_SIGNING_KEYS =
      "public:ccf.gov.jwt.public_signing_keys";
    static constexpr auto JWT_PUBLIC_SIGNING_KEY_ISSUER =
      "public:ccf.gov.jwt.public_signing_key_issuer";

    // Internal only
    static constexpr auto SECRETS = "public:ccf.internal.secrets";
    static constexpr auto SHARES = "public:ccf.internal.shares";
    static constexpr auto SUBMITTED_SHARES =
      "public:ccf.intenal.encrypted_submitted_shares";
    static constexpr auto SNAPSHOT_EVIDENCE =
      "public:ccf.internal.snapshot_evidence";
    static constexpr auto SIGNATURES = "public:ccf.internal.signatures";

    // Consensus
    static constexpr auto CONSENSUS = "public:ccf.internal.consensus";
    static constexpr auto AFT_REQUESTS = "ccf.internal.consensus.requests";
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