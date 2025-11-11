// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::endpoints
{
  enum class OperatorFeature
  {
    SnapshotRead,
  };

  DECLARE_JSON_ENUM(
    OperatorFeature,
    {
      {OperatorFeature::SnapshotRead, "SnapshotRead"},
    });
}
