// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/tls_endpoint.h"
#include "http_builder.h"

#include <algorithm>
#include <cctype>
#include <endian.h>
#include <http-parser/http_parser.h>
#include <map>
#include <queue>
#include <string>

namespace http
{
  class RequestProcessor
  {
  public:
    virtual void handle_request(
      http_method method,
      const std::string_view& path,
      const std::string& query,
      HeaderMap&& headers,
      std::vector<uint8_t>&& body) = 0;
  };

  class ResponseProcessor
  {
  public:
    virtual void handle_response(
      http_status status, HeaderMap&& headers, std::vector<uint8_t>&& body) = 0;
  };
}