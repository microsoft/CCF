// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "http/http_status.h"

namespace ccf
{
  struct ODataError
  {
    std::string code;
    std::string message;
  };

  DECLARE_JSON_TYPE(ODataError);
  DECLARE_JSON_REQUIRED_FIELDS(ODataError, code, message);

  struct ODataErrorResponse
  {
    ODataError error;
  };

  DECLARE_JSON_TYPE(ODataErrorResponse);
  DECLARE_JSON_REQUIRED_FIELDS(ODataErrorResponse, error);

  struct ErrorDetails
  {
    http_status status;
    std::string code;
    std::string msg;
  };
}