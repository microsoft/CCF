// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tracing/trace.h"

namespace ccf::reconfiguration::trace
{
  DECLARE_TRACE_EVENT(
    retired_committed_tx, "ccf.cft", node_id, seqno, retired_node_id);
}
