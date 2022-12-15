// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_header_map.h"
#include "ccf/odata_error.h"

#include <functional>

namespace http
{
  using StreamOnCloseCallback = std::function<void(void)>;

  class HTTPResponder
  {
  public:
    virtual ~HTTPResponder() = default;

    virtual bool send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      http::HeaderMap&& trailers,
      std::span<const uint8_t> body) = 0;

    virtual bool start_stream(
      http_status status, const http::HeaderMap& headers) = 0;

    virtual bool stream_data(std::span<const uint8_t> data) = 0;

    virtual bool close_stream(http::HeaderMap&& trailers) = 0;

    virtual bool set_on_stream_close_callback(StreamOnCloseCallback cb) = 0;

    bool send_odata_error_response(ccf::ErrorDetails&& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      const auto s = body.dump();

      http::HeaderMap headers;
      headers[http::headers::CONTENT_TYPE] =
        http::headervalues::contenttype::JSON;

      return send_response(
        error.status,
        std::move(headers),
        {},
        {(const uint8_t*)s.data(), s.size()});
    }
  };
}
