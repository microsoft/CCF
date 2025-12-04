// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/tls_session.h"
#include "http2_types.h"
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
  class RequestProcessor
  {
  public:
    virtual ~RequestProcessor() = default;

    virtual void handle_request(
      llhttp_method method,
      const std::string_view& url,
      ccf::http::HeaderMap&& headers,
      std::vector<uint8_t>&& body,
      int32_t stream_id = http2::DEFAULT_STREAM_ID) = 0;
  };

  class ResponseProcessor
  {
  public:
    virtual ~ResponseProcessor() = default;

    virtual void handle_response(
      ccf::http_status status,
      ccf::http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) = 0;
  };
}