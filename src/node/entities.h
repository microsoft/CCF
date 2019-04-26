// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "kv/kv.h"
#include "kv/kvserialiser.h"

#include <limits>
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
  using CaId = ObjectId;
  using Cert = std::vector<uint8_t>;
  using CodeVersion = ObjectId;

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

  struct Tables
  {
    static constexpr auto MEMBERS = "members";
    static constexpr auto MEMBER_ACKS = "memberacks";
    static constexpr auto MEMBER_CERTS = "membercerts";
    static constexpr auto USER_CERTS = "usercerts";
    static constexpr auto NODE_CERTS = "nodecerts";
    static constexpr auto NODES = "nodes";
    static constexpr auto VALUES = "values";
    static constexpr auto ATTESTATION_CAS = "attestationcas";
    static constexpr auto SEQ_NOS = "seqnos";
    static constexpr auto APP = "app";
    static constexpr auto APP_AUX = "app_aux";
    static constexpr auto APP_PUBLIC = "app_public";
    static constexpr auto SIGNATURES = "signatures";
    static constexpr auto USER_CLIENT_SIGNATURES = "userclientsignatures";
    static constexpr auto MEMBER_CLIENT_SIGNATURES = "memberclientsignatures";
    static constexpr auto WHITELISTS = "whitelists";
    static constexpr auto PROPOSALS = "proposals";
    static constexpr auto GOV_SCRIPTS = "govscripts";
    static constexpr auto APP_SCRIPTS = "appscripts";
    static constexpr auto SECRETS = "secrets";
    static constexpr auto CODEID = "codeid";
  };

  using StoreSerialiser = kv::KvStoreSerialiser;
  using StoreDeserialiser = kv::KvStoreDeserialiser;
  using Store = kv::Store<StoreSerialiser, StoreDeserialiser>;
}
