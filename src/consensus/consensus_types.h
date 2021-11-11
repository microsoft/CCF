// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/nodes.h"

#include <stdint.h>

namespace consensus
{
  struct Configuration
  {
    ConsensusType type = ConsensusType::CFT;
    size_t raft_timeout_ms;
    size_t raft_election_timeout_ms;
    size_t bft_view_change_timeout; // TODO: Make optional
    size_t bft_status_interval; // TODO: Make optional

    bool operator==(const Configuration&) const = default;
    bool operator!=(const Configuration&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration,
    type,
    raft_timeout_ms,
    raft_election_timeout_ms,
    bft_view_change_timeout,
    bft_status_interval);

#pragma pack(push, 1)
  template <typename T>
  struct ConsensusHeader
  {
    ConsensusHeader() = default;
    ConsensusHeader(T msg_) : msg(msg_) {}

    T msg;
  };

  struct AppendEntriesIndex
  {
    ccf::SeqNo idx;
    ccf::SeqNo prev_idx;
  };
#pragma pack(pop)
}