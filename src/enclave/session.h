// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "http/http_builder.h"

#include <sys/socket.h>
#include <vector>

namespace ccf
{
  class Session : public std::enable_shared_from_this<Session>
  {
  public:
    virtual ~Session() = default;

    // TODO: Spans?
    virtual void handle_incoming_data(const uint8_t* data, size_t size) = 0;
    virtual void send_data(const uint8_t* data, size_t size) = 0;
    virtual void send_data(std::vector<uint8_t>&& data)
    {
      send_data(data.data(), data.size());
    }

    virtual void send_response(http::Response&& resp)
    {
      send_data(resp.build_response());
    }

    void send_odata_error_response(ccf::ErrorDetails&& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg)}};
      const auto s = body.dump();

      std::vector<uint8_t> data(s.begin(), s.end());
      auto response = http::Response(error.status);

      response.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
      response.set_body(&data);

      send_response(std::move(response));
    }

    virtual void send_request_oops(http::Request&& req)
    {
      send_data(req.build_request());
    }

    virtual void close() = 0;
  };
}
