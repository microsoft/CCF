// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/nodes.h"

#include <msgpack/msgpack.hpp>
#include <stdint.h>

namespace consensus
{
  struct Configuration
  {
    size_t raft_request_timeout;
    size_t raft_election_timeout;
    size_t bft_view_change_timeout;
    size_t bft_status_interval;
    MSGPACK_DEFINE(
      raft_request_timeout,
      raft_election_timeout,
      bft_view_change_timeout,
      bft_status_interval);
  };

#pragma pack(push, 1)
  template <typename T>
  struct ConsensusHeader
  {
    ConsensusHeader() = default;
    ConsensusHeader(T msg_) : msg(msg_) {}

    T msg;
    // ccf::NodeId from_node;
  };

  struct AppendEntriesIndex
  {
    ccf::Index idx;
    ccf::Index prev_idx;
  };
#pragma pack(pop)
}