// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"

namespace http
{
  class HTTPResponder
  {
  public:
    virtual ~HTTPResponder() = default;

    virtual void send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      http::HeaderMap&& trailers,
      std::span<const uint8_t> body) = 0;

    void send_odata_error_response(ccf::ErrorDetails&& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      const auto s = body.dump();

      http::HeaderMap headers;
      headers[http::headers::CONTENT_TYPE] =
        http::headervalues::contenttype::JSON;

      send_response(
        error.status,
        std::move(headers),
        {},
        {(const uint8_t*)s.data(), s.size()});
    }
  };
}
