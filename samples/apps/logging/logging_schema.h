// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/ds/json.h"
#include "ccf/receipt.h"

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
      bool record_claim = false;
    };
  };

  struct LoggingGet
  {
    struct Out
    {
      std::string msg;
    };
  };

  struct LoggingRemove
  {
    using Out = bool;
  };

  struct LoggingPut
  {
    struct Out
    {
      bool success;
      std::string tx_id;
    };
  };

  struct LoggingGetReceipt
  {
    struct In
    {
      size_t id;
    };

    struct Out
    {
      std::string msg;
      nlohmann::json receipt;
    };
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(LoggingRecord::In);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingRecord::In, id, msg);
  DECLARE_JSON_OPTIONAL_FIELDS(LoggingRecord::In, record_claim);

  DECLARE_JSON_TYPE(LoggingGet::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGet::Out, msg);

  DECLARE_JSON_TYPE(LoggingPut::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingPut::Out, success, tx_id);

  DECLARE_JSON_TYPE(LoggingGetReceipt::In);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGetReceipt::In, id);
  DECLARE_JSON_TYPE(LoggingGetReceipt::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGetReceipt::Out, msg, receipt);

  // SNIPPET_END: macro_validation_macros

  using LoggingGetHistorical = LoggingGet;

  struct LoggingGetHistoricalRange
  {
    struct Entry
    {
      size_t seqno;
      size_t id;
      std::string msg;
    };

    struct Out
    {
      std::vector<Entry> entries;
      std::optional<std::string> next_link;
    };
  };
  DECLARE_JSON_TYPE(LoggingGetHistoricalRange::Entry);
  DECLARE_JSON_REQUIRED_FIELDS(
    LoggingGetHistoricalRange::Entry, seqno, id, msg);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(LoggingGetHistoricalRange::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGetHistoricalRange::Out, entries);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    LoggingGetHistoricalRange::Out, next_link, "@nextLink");

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