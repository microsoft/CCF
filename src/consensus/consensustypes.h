// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <msgpack.hpp>
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
    size_t request_timeout;
    size_t election_timeout;
    size_t status_timeout;
    MSGPACK_DEFINE(request_timeout, election_timeout);
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