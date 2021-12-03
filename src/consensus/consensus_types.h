// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "common/unit_strings.h"
#include "node/nodes.h"

#include <stdint.h>

namespace consensus
{
  struct Configuration
  {
    ConsensusType type = ConsensusType::CFT;
    TimeString timeout = 100'000; // TODO: it would be nice to have a better
                                  // ctor to avoid these huge numbers!
    TimeString election_timeout = 5'000'000;

    bool operator==(const Configuration&) const = default;
    bool operator!=(const Configuration&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration);
  DECLARE_JSON_OPTIONAL_FIELDS(Configuration, type, timeout, election_timeout);

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