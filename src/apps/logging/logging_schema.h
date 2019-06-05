// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"

namespace ccf
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

  DECLARE_REQUIRED_JSON_FIELDS(LoggingRecord::In, id, msg);

  DECLARE_REQUIRED_JSON_FIELDS(LoggingGet::In, id);
  DECLARE_REQUIRED_JSON_FIELDS(LoggingGet::Out, msg);
  // SNIPPET_END: macro_validation_macros

  // Public record/get
  // Manual schemas, verified then parsed in handler
  static const std::string j_record_public = R"!!!(
  {
    "$schema": "http://json-schema.org/draft-07/schema#",
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
    "title": "LOG_record_pub/params",
    "type": "object"
  }
  )!!!";

  static const std::string j_get_public_in = R"!!!(
  {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "properties": {
      "id": {
        "type": "number"
      }
    },
    "required": [
      "id"
    ],
    "title": "LOG_get_pub/params",
    "type": "object"
  }
  )!!!";

  static const std::string j_get_public_out = R"!!!(
  {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "properties": {
      "msg": {
        "type": "string"
      }
    },
    "required": [
      "msg"
    ],
    "title": "LOG_get_pub/result",
    "type": "object"
  }
  )!!!";
}