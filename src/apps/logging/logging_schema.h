// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"

namespace loggingapp
{
  // Private record/get
  // Explicit target structs, macro-generated parsers + schema
  // SNIPPET_START: macro_validation_macros
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

  struct LoggingRemove
  {
    using In = LoggingGet::In;

    using Out = bool;
  };

  DECLARE_JSON_TYPE(LoggingRecord::In);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingRecord::In, id, msg);

  DECLARE_JSON_TYPE(LoggingGet::In);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGet::In, id);
  DECLARE_JSON_TYPE(LoggingGet::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGet::Out, msg);
  // SNIPPET_END: macro_validation_macros

  using LoggingGetHistorical = LoggingGet;

  // Public record/get
  // Manual schemas, verified then parsed in handler
  static const std::string j_record_public_in = R"!!!(
  {
    "properties": {
      "id": {
        "type": "number"
      },
      "msg": {
        "type": "string"
      }
    },
    "required": [
      "id",
      "msg"
    ],
    "title": "log/public/params",
    "type": "object"
  }
  )!!!";

  static const std::string j_record_public_out = R"!!!(
  {
    "title": "log/public/result",
    "type": "boolean"
  }
  )!!!";

  static const std::string j_get_public_in = R"!!!(
  {
    "properties": {
      "id": {
        "type": "number"
      }
    },
    "required": [
      "id"
    ],
    "title": "log/public/params",
    "type": "object"
  }
  )!!!";

  static const std::string j_get_public_out = R"!!!(
  {
    "properties": {
      "msg": {
        "type": "string"
      }
    },
    "required": [
      "msg"
    ],
    "title": "log/public/result",
    "type": "object"
  }
  )!!!";
}