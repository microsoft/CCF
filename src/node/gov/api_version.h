// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf::gov::endpoints
{
  enum class ApiVersion
  {
    v0_0_1_preview
  };

  DECLARE_JSON_ENUM(
    ApiVersion, {{ApiVersion::v0_0_1_preview, "0.0.1-preview"}});

  // TODO: Add a decorator to extract api-version?
}