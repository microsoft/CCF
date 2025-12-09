// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf::crypto
{
  enum class MDType : uint8_t
  {
    NONE = 0,
    SHA1,
    SHA256,
    SHA384,
    SHA512
  };

  DECLARE_JSON_ENUM(
    MDType,
    {{MDType::NONE, "NONE"},
     {MDType::SHA1, "SHA1"},
     {MDType::SHA256, "SHA256"},
     {MDType::SHA384, "SHA384"},
     {MDType::SHA512, "SHA512"}});
}
