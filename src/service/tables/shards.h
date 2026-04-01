// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/json.h"
#include "ccf/service/map.h"
#include "kv/kv_types.h"

#include <string>

namespace ccf
{
  enum class ShardStatus : uint8_t
  {
    Active = 0,
    Sealing = 1,
    Sealed = 2
  };

  DECLARE_JSON_ENUM(
    ShardStatus,
    {{ShardStatus::Active, "Active"},
     {ShardStatus::Sealing, "Sealing"},
     {ShardStatus::Sealed, "Sealed"}});

  struct ShardInfo
  {
    uint64_t shard_id = 0;
    ccf::kv::Version seqno_start = 0;
    ccf::kv::Version seqno_end = 0;
    ccf::kv::Version snapshot_seqno = 0;
    ccf::crypto::Sha256Hash merkle_root_at_seal = {};
    ccf::kv::Version ledger_secret_version = 0;
    ShardStatus status = ShardStatus::Active;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ShardInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    ShardInfo, shard_id, seqno_start, seqno_end, status);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ShardInfo,
    snapshot_seqno,
    merkle_root_at_seal,
    ledger_secret_version);

  using Shards = ServiceMap<uint64_t, ShardInfo>;

  struct ShardPolicyInfo
  {
    size_t auto_seal_after_seqno_count = 0;
    size_t auto_seal_after_duration_s = 0;
    size_t max_active_shard_memory_mb = 0;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ShardPolicyInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ShardPolicyInfo);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ShardPolicyInfo,
    auto_seal_after_seqno_count,
    auto_seal_after_duration_s,
    max_active_shard_memory_mb);

  using ShardPolicy = ServiceValue<ShardPolicyInfo>;

  namespace Tables
  {
    static constexpr auto SHARDS = "public:ccf.gov.shards.info";
    static constexpr auto SHARD_POLICY = "public:ccf.gov.shards.policy";
  }
}
