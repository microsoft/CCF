// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"

namespace ccf
{
  struct LoggingRecord
  {
    struct In
    {
      size_t id;
      std::string msg;
    };
  };

  struct LoggingGet
  {
    struct In
    {
      size_t id;
    };

    struct Out
    {
      std::string msg;
    };
  };

  DECLARE_REQUIRED_JSON_FIELDS(LoggingRecord::In, id, msg);

  DECLARE_REQUIRED_JSON_FIELDS(LoggingGet::In, id);
  DECLARE_REQUIRED_JSON_FIELDS(LoggingGet::Out, msg);
}