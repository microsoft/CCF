// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <ccf/tx_id.h>

namespace ccf
{
  using ReconfigurationId = uint64_t;

  typedef struct
  {
    // SeqNo at which a resharing for a reconfiguration was completed
    SeqNo seqno;
    ReconfigurationId reconfiguration_id;
    uint64_t splitid_session_id;
  } ResharingResult;

  DECLARE_JSON_TYPE(ResharingResult)
  DECLARE_JSON_REQUIRED_FIELDS(
    ResharingResult, seqno, reconfiguration_id, splitid_session_id)
}
