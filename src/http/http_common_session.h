// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "enclave/session.h"

namespace http
{
  template <typename Base>
  class HTTPCommonSession : public Base
  {
  public:
    using Base::Base;

    // TODO: Should exist at a lower-level - HttpCommonSession?
    virtual void send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      std::span<const uint8_t> body) = 0;
    // TODO: This variant is extremely wrong...
    virtual void send_response(
      int32_t stream_id,
      http_status status_code,
      http::HeaderMap&& headers,
      std::span<const uint8_t> body)
    {
      send_response(status_code, std::move(headers), body);
    }

    void send_odata_error_response(ccf::ErrorDetails&& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      const auto s = body.dump();

      http::HeaderMap headers;
      headers[http::headers::CONTENT_TYPE] =
        http::headervalues::contenttype::JSON;

      send_response(
        error.status, std::move(headers), {(const uint8_t*)s.data(), s.size()});
    }

    virtual void send_request_oops(http::Request&& req)
    {
      Base::send_data(req.build_request());
    }
  };
}
