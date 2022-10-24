// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http/http_builder.h"
#include "tls/msg_types.h"

namespace ccf
{
  class ClientSession
  {
  public:
    using HandleDataCallback = std::function<void(
      http_status status,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body)>;

    using HandleErrorCallback =
      std::function<void(const std::string& error_msg)>;

  protected:
    HandleDataCallback handle_data_cb;
    HandleErrorCallback handle_error_cb;

  private:
    int64_t client_session_id;
    ringbuffer::WriterPtr to_host;

  public:
    ClientSession(
      int64_t client_session_id,
      ringbuffer::AbstractWriterFactory& writer_factory) :
      client_session_id(client_session_id),
      to_host(writer_factory.create_writer_to_outside())
    {}

    virtual void send_request(http::Request&& request) = 0;

    virtual void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f,
      const HandleErrorCallback e = nullptr)
    {
      RINGBUFFER_WRITE_MESSAGE(
        tls::tls_connect, to_host, client_session_id, hostname, service);
      handle_data_cb = f;
      handle_error_cb = e;
    }
  };
}
