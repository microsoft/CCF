// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <msgpack/msgpack.hpp>
#include <stdint.h>

namespace ccf
{
  using ObjectId = uint64_t;
  using NodeId = ObjectId;
  using Index = int64_t;
  using Node2NodeMsg = uint64_t;
}

namespace consensus
{
  struct Config
  {
    size_t raft_request_timeout;
    size_t raft_election_timeout;
    size_t pbft_view_change_timeout;
    size_t pbft_status_interval;
    MSGPACK_DEFINE(
      raft_request_timeout,
      raft_election_timeout,
      pbft_view_change_timeout,
      pbft_status_interval);
  };

#pragma pack(push, 1)
  template <typename T = ccf::Node2NodeMsg>
  struct ConsensusHeader
  {
    T msg;
    ccf::NodeId from_node;
  };

  struct AppendEntriesIndex
  {
    ccf::Index idx;
    ccf::Index prev_idx;
  };
#pragma pack(pop)
}