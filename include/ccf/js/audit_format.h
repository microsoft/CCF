// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ccf/ds/json.h"

#include <vector>

namespace ccf
{
  enum class ActionFormat : uint8_t
  {
    COSE = 0,
    JSON = 1
  };
  DECLARE_JSON_ENUM(
    ActionFormat, {{ActionFormat::COSE, "COSE"}, {ActionFormat::JSON, "JSON"}});

  struct AuditInfo
  {
    ActionFormat format;
    // Deliberately a string and not a ccf::UserId to allow extended usage, for
    // example with OpenID
    std::string user_id;
    // Format left to the application, Verb + URL with some of kind of
    // versioning is recommended
    std::string action_name;
  };

  DECLARE_JSON_TYPE(AuditInfo);
  DECLARE_JSON_REQUIRED_FIELDS(AuditInfo, format, user_id, action_name);
}