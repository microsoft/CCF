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
    static constexpr auto MEMBERS = "ccf.members";
    static constexpr auto MEMBER_ACKS = "ccf.member_acks";
    static constexpr auto MEMBER_CERT_DERS = "ccf.member_cert_ders";
    static constexpr auto USERS = "ccf.users";
    static constexpr auto USER_CERT_DERS = "ccf.user_cert_ders";
    static constexpr auto NODES = "ccf.nodes";
    static constexpr auto VALUES = "ccf.values";
    static constexpr auto SIGNATURES = "ccf.signatures";
    static constexpr auto CONSENSUS = "ccf.consensus";
    static constexpr auto USER_CLIENT_SIGNATURES = "ccf.user_client_signatures";
    static constexpr auto MEMBER_CLIENT_SIGNATURES =
      "ccf.member_client_signatures";
    static constexpr auto WHITELISTS = "ccf.whitelists";
    static constexpr auto PROPOSALS = "ccf.proposals";
    static constexpr auto GOV_SCRIPTS = "ccf.governance.scripts";
    static constexpr auto APP_SCRIPTS = "ccf.app_scripts";
    static constexpr auto MODULES = "ccf.modules";
    static constexpr auto SECRETS = "ccf.secrets";
    static constexpr auto NODE_CODE_IDS = "ccf.nodes.code_ids";
    static constexpr auto GOV_HISTORY = "ccf.governance.history";
    static constexpr auto SERVICE = "ccf.service";
    static constexpr auto SHARES = "ccf.shares";
    static constexpr auto USER_CODE_IDS = "ccf.users.code_ids";
    static constexpr auto CONFIGURATION = "ccf.config";
    static constexpr auto SUBMITTED_SHARES = "ccf.submitted_shares";
    static constexpr auto SNAPSHOT_EVIDENCE = "ccf.snapshot_evidence";
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