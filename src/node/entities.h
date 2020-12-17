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
    // Governance tables
    static constexpr auto MEMBERS = "public:ccf.gov.members";
    static constexpr auto MEMBER_ACKS = "public:ccf.gov.member_acks";
    static constexpr auto MEMBER_CERT_DERS = "public:ccf.gov.member_cert_ders";
    static constexpr auto MEMBER_DIGESTS = "public:ccf.gov.member_digests";
    static constexpr auto USERS = "public:ccf.gov.users";
    static constexpr auto USER_CERT_DERS = "public:ccf.gov.user_cert_ders";
    static constexpr auto USER_DIGESTS = "public:ccf.gov.user_digests";
    static constexpr auto NODES = "public:ccf.gov.nodes";
    static constexpr auto VALUES = "public:ccf.gov.values";
    static constexpr auto CONSENSUS = "public:ccf.gov.consensus";
    static constexpr auto WHITELISTS = "public:ccf.gov.whitelists";
    static constexpr auto PROPOSALS = "public:ccf.gov.proposals";
    static constexpr auto GOV_SCRIPTS = "public:ccf.gov.governance.scripts";
    static constexpr auto APP_SCRIPTS = "public:ccf.gov.app_scripts";
    static constexpr auto MODULES = "public:ccf.gov.modules";
    static constexpr auto SECRETS = "public:ccf.gov.secrets";
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
    static constexpr auto GOV_HISTORY = "public:ccf.gov.governance.history";
    static constexpr auto SERVICE = "public:ccf.gov.service";
    static constexpr auto SHARES = "public:ccf.gov.shares";
    static constexpr auto CONFIGURATION = "public:ccf.gov.config";
    static constexpr auto SUBMITTED_SHARES = "public:ccf.gov.submitted_shares";
    static constexpr auto SNAPSHOT_EVIDENCE =
      "public:ccf.gov.snapshot_evidence";
    static constexpr auto CA_CERT_DERS = "public:ccf.gov.ca_cert_ders";
    static constexpr auto JWT_ISSUERS = "public:ccf.gov.jwt_issuers";
    static constexpr auto JWT_PUBLIC_SIGNING_KEYS =
      "public:ccf.gov.jwt_public_signing_keys";
    static constexpr auto JWT_PUBLIC_SIGNING_KEY_ISSUER =
      "public:ccf.gov.jwt_public_signing_key_issuer";
    static constexpr auto ENDPOINTS = "public:ccf.gov.endpoints";

    static constexpr auto SIGNATURES = "public:ccf.internal.signatures";

    static constexpr auto BACKUP_SIGNATURES =
      "public:ccf.internal.backup_signatures";
    static constexpr auto NONCES = "public:ccf.internal.nonces";

    // Consensus specific tables
    static constexpr auto AFT_REQUESTS = "public:ccf.gov.aft.requests";
    static constexpr auto NEW_VIEWS = "public:ccf.internal.new_views";
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