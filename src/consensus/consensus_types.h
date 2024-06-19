// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/unit_strings.h"
#include "ccf/service/consensus_config.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/tx_id.h"
#include "enclave/consensus_type.h"

#include <stdint.h>

namespace ccf::consensus
{
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration, message_timeout, election_timeout, max_uncommitted_tx_count);

}

namespace consensus
{
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
  DECLARE_JSON_TYPE(AppendEntriesIndex);
  DECLARE_JSON_REQUIRED_FIELDS(AppendEntriesIndex, idx, prev_idx);

#pragma pack(pop)
}