// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/unit_strings.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/tx_id.h"
#include "enclave/consensus_type.h"

#include <stdint.h>

namespace consensus
{
  struct Configuration
  {
    ConsensusType type = ConsensusType::CFT;
    ds::TimeString message_timeout = {"100ms"};
    ds::TimeString election_timeout = {"5000ms"};

    bool operator==(const Configuration&) const = default;
    bool operator!=(const Configuration&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration, type, message_timeout, election_timeout);

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