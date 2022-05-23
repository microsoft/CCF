// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/tx_id.h"
#include "kv/kv_types.h"

namespace ccf
{
  using ReconfigurationId = uint64_t;

  struct ResharingResult
  {
    // SeqNo at which a resharing for a reconfiguration was completed
    SeqNo seqno;
    ReconfigurationId reconfiguration_id;
  };

  DECLARE_JSON_TYPE(ResharingResult)
  DECLARE_JSON_REQUIRED_FIELDS(ResharingResult, seqno, reconfiguration_id)
}
