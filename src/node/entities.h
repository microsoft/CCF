// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "kv/kv.h"
#include "kv/kvserialiser.h"

#include <limits>
#include <map>
#include <stdint.h>
#include <vector>

namespace ccf
{
  using ObjectId = uint64_t;
  constexpr ObjectId INVALID_ID = (std::numeric_limits<ObjectId>::max)();

  using MemberId = ObjectId;
  using NodeId = ObjectId;
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
    static constexpr auto MANAGEMENT = "management";
  };

  enum ActorsType : uint64_t
  {
    members = 0,
    users,
    nodes,
    management,
    // not to be used
    unknown
  };

  struct Tables
  {
    static constexpr auto MEMBERS = "ccf.members";
    static constexpr auto MEMBER_ACKS = "ccf.member_acks";
    static constexpr auto MEMBER_CERTS = "ccf.member_certs";
    static constexpr auto USER_CERTS = "ccf.user_certs";
    static constexpr auto NODE_CERTS = "ccf.node_certs";
    static constexpr auto NODES = "ccf.nodes";
    static constexpr auto VALUES = "ccf.values";
    static constexpr auto SIGNATURES = "ccf.signatures";
    static constexpr auto USER_CLIENT_SIGNATURES = "ccf.user_client_signatures";
    static constexpr auto MEMBER_CLIENT_SIGNATURES =
      "ccf.member_client_signatures";
    static constexpr auto WHITELISTS = "ccf.whitelists";
    static constexpr auto PROPOSALS = "ccf.proposals";
    static constexpr auto GOV_SCRIPTS = "ccf.gov_scripts";
    static constexpr auto APP_SCRIPTS = "ccf.app_scripts";
    static constexpr auto SECRETS = "ccf.secrets";
    static constexpr auto CODE_IDS = "ccf.code_ids";
    static constexpr auto VOTING_HISTORY = "ccf.voting_history";
    static constexpr auto SERVICE = "ccf.service";
  };

  using StoreSerialiser = kv::KvStoreSerialiser;
  using StoreDeserialiser = kv::KvStoreDeserialiser;
  using Store = kv::Store<StoreSerialiser, StoreDeserialiser>;
}
