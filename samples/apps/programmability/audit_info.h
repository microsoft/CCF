// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ccf/ds/json.h"
#include "ccf/entity_id.h"

#include <vector>

namespace programmabilityapp
{
  enum class AuditInputFormat
  {
    COSE = 0,
    JSON = 1
  };
  DECLARE_JSON_ENUM(
    AuditInputFormat,
    {{AuditInputFormat::COSE, "COSE"}, {AuditInputFormat::JSON, "JSON"}});

  enum class AuditInputContent
  {
    BUNDLE = 0,
    OPTIONS = 1
  };
  DECLARE_JSON_ENUM(
    AuditInputContent,
    {{AuditInputContent::BUNDLE, "BUNDLE"},
     {AuditInputContent::OPTIONS, "OPTIONS"}});

  struct AuditInfo
  {
    AuditInputFormat format;
    AuditInputContent content;
    ccf::UserId user_id;
  };

  DECLARE_JSON_TYPE(AuditInfo)
  DECLARE_JSON_REQUIRED_FIELDS(AuditInfo, format, content, user_id)
}