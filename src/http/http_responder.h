// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "ccf/pal/locking.h"
#include "http/responder_lookup_interface.h"

#include <map>

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

  class ResponderLookup : public AbstractResponderLookup
  {
  protected:
    using ByStream =
      std::unordered_map<http2::StreamId, std::shared_ptr<HTTPResponder>>;

    std::unordered_map<tls::ConnID, ByStream> all_responders;

    // Responder lookup is shared by all HTTP sessions
    ccf::pal::Mutex lock;

  public:
    std::shared_ptr<HTTPResponder> lookup_responder(
      tls::ConnID session_id, http2::StreamId stream_id)
    {
      std::unique_lock<ccf::pal::Mutex> guard(lock);
      auto conn_it = all_responders.find(session_id);
      if (conn_it != all_responders.end())
      {
        auto& by_stream = conn_it->second;
        auto stream_it = by_stream.find(stream_id);
        if (stream_it != by_stream.end())
        {
          return stream_it->second;
        }
      }

      return nullptr;
    }

    void add_responder(
      tls::ConnID session_id,
      http2::StreamId stream_id,
      std::shared_ptr<HTTPResponder> responder)
    {
      std::unique_lock<ccf::pal::Mutex> guard(lock);
      all_responders[session_id][stream_id] = responder;
    }

    void cleanup_responders(tls::ConnID session_id)
    {
      std::unique_lock<ccf::pal::Mutex> guard(lock);
      all_responders.erase(session_id);
    }
  };
}
