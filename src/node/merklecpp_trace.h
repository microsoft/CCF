// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

// Use the CCF logging infrastructure for merklecpp traces.
#define MERKLECPP_TRACE_ENABLED
#define MERKLECPP_TRACE(X) \
  { \
    X; \
  };
#define MERKLECPP_TOUT CCF_LOG_OUT(TRACE, "merkl")
