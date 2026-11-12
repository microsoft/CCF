// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/json.h"
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

  CCF_JSON_TYPE(
    LoggingRecord::In,
    CCF_JSON_REQUIRED(id, msg),
    CCF_JSON_OPTIONAL(record_claim));
  CCF_JSON_TYPE(LoggingGet::Out, CCF_JSON_REQUIRED(msg));
  CCF_JSON_TYPE(LoggingPut::Out, CCF_JSON_REQUIRED(success, tx_id));
  CCF_JSON_TYPE(LoggingGetReceipt::In, CCF_JSON_REQUIRED(id));
  CCF_JSON_TYPE(LoggingGetReceipt::Out, CCF_JSON_REQUIRED(msg, receipt));

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

  CCF_JSON_TYPE(
    LoggingGetHistoricalRange::Entry, CCF_JSON_REQUIRED(seqno, id, msg));
  CCF_JSON_TYPE(
    LoggingGetHistoricalRange::Out,
    CCF_JSON_REQUIRED(entries),
    CCF_JSON_NAMED(Optional, next_link, "@nextLink"));

  struct LoggingGetCoseEndorsements
  {
    struct Out
    {
      std::optional<ccf::SerialisedCoseEndorsements> endorsements;
    };
  };

  DECLARE_JSON_TYPE(LoggingGetCoseEndorsements::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGetCoseEndorsements::Out, endorsements);

  struct LoggingGetCoseSignature
  {
    struct Out
    {
      ccf::SerialisedCoseSignature cose_signature;
    };
  };

  DECLARE_JSON_TYPE(LoggingGetCoseSignature::Out);
  DECLARE_JSON_REQUIRED_FIELDS(LoggingGetCoseSignature::Out, cose_signature);

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