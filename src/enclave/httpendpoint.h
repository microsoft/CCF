// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpparser.h"

namespace enclave
{
  template <class E>
  class HTTPEndpoint : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;

  public:
    HTTPEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) = delete;

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      LOG_TRACE_FMT("recv called with {} bytes", size);

      auto buf = read_all_available();

      if (buf.size() == 0)
      {
        return;
      }

      LOG_TRACE_FMT(
        "Going to parse {} bytes: [{}]",
        buf.size(),
        std::string(buf.begin(), buf.end()));

      // TODO: This should return an error to the client if this fails
      if (p.execute(buf.data(), buf.size()) == 0)
      {
        LOG_FAIL_FMT("Failed to parse request");
        return;
      }
    }

    virtual void msg(
      http_method method,
      const std::string& path,
      const std::string& query,
      std::vector<uint8_t> body)
    {
      if (body.size() > 0)
      {
        try
        {
          // if (!handle_data(body))
          {
            close();
          }
        }
        catch (...)
        {
          // On any exception, close the connection.
          close();
        }
      }
    }

    void send(const std::vector<uint8_t>& data)
    {
      send_buffered(E::emit(data));
      if (data.size() > 0)
      {
        send_buffered(data);
      }
      flush();
    }
  };

  template <>
  HTTPEndpoint<http::RequestHeaderEmitter>::HTTPEndpoint(
    size_t session_id,
    ringbuffer::AbstractWriterFactory& writer_factory,
    std::unique_ptr<tls::Context> ctx) :
    TLSEndpoint(session_id, writer_factory, std::move(ctx)),
    p(HTTP_RESPONSE, *this)
  {}

  template <>
  HTTPEndpoint<http::ResponseHeaderEmitter>::HTTPEndpoint(
    size_t session_id,
    ringbuffer::AbstractWriterFactory& writer_factory,
    std::unique_ptr<tls::Context> ctx) :
    TLSEndpoint(session_id, writer_factory, std::move(ctx)),
    p(HTTP_REQUEST, *this)
  {}
}