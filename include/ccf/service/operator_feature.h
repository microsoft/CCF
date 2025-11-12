// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf::endpoints
{
  enum class OperatorFeature : uint8_t
  {
    SnapshotRead,
  };

  DECLARE_JSON_ENUM(
    OperatorFeature,
    {
      {OperatorFeature::SnapshotRead, "SnapshotRead"},
    });
}
