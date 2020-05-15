// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/consensus_types.h"
#include "kv/kv.h"
#include "kv/kv_serialiser.h"

#include <limits>
#include <map>
#include <stdint.h>
#include <vector>

namespace ccf
{
  constexpr ObjectId INVALID_ID = (std::numeric_limits<ObjectId>::max)();

  using MemberId = ObjectId;
  using UserId = ObjectId;
  using CallerId = ObjectId;
  using Cert = std::vector<uint8_t>;

  // SGX MRENCLAVE is SHA256 digest
  static constexpr size_t CODE_DIGEST_BYTES = 256 / 8;
  using CodeDigest = std::array<uint8_t, CODE_DIGEST_BYTES>;

  struct Actors
  {
    static constexpr auto MEMBERS = "members";
    static constexpr auto USERS = "users";
    static constexpr auto NODES = "nodes";
  };

  enum class ActorsType : uint64_t
  {
    members = 0,
    users,
    nodes,
    // not to be used
    unknown
  };

  struct Tables
  {
    static constexpr auto MEMBERS = "ccf.members";
    static constexpr auto MEMBER_ACKS = "ccf.member_acks";
    static constexpr auto MEMBER_CERTS = "ccf.member_certs";
    static constexpr auto USERS = "ccf.users";
    static constexpr auto USER_CERTS = "ccf.user_certs";
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
    static constexpr auto SECRETS = "ccf.secrets";
    static constexpr auto NODE_CODE_IDS = "ccf.nodes.code_ids";
    static constexpr auto GOV_HISTORY = "ccf.governance.history";
    static constexpr auto SERVICE = "ccf.service";
    static constexpr auto SHARES = "ccf.shares";
    static constexpr auto USER_CODE_IDS = "ccf.users.code_ids";
    static constexpr auto CONFIGURATION = "ccf.config";
  };

  using StoreSerialiser = kv::KvStoreSerialiser;
  using StoreDeserialiser = kv::KvStoreDeserialiser;
  using Store = kv::Store<StoreSerialiser, StoreDeserialiser>;
}

namespace enclave
{
  enum FrameFormat : uint8_t
  {
    http = 0,
    ws
  };
}