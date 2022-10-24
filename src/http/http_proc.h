// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/tls_session.h"
#include "http_builder.h"

#include <algorithm>
#include <cctype>
#include <endian.h>
#include <llhttp/llhttp.h>
#include <map>
#include <queue>
#include <string>

namespace http
{
  // Only used for HTTP/2
  constexpr static int32_t DEFAULT_STREAM_ID = 0;

  class RequestProcessor
  {
  public:
    virtual void handle_request(
      llhttp_method method,
      const std::string_view& url,
      HeaderMap&& headers,
      std::vector<uint8_t>&& body,
      int32_t stream_id = DEFAULT_STREAM_ID) = 0;
  };

  class ResponseProcessor
  {
  public:
    virtual void handle_response(
      http_status status, HeaderMap&& headers, std::vector<uint8_t>&& body) = 0;
  };
}