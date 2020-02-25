// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/msg_types.h"

namespace enclave
{
  class ClientEndpoint
  {
  protected:
    using HandleDataCallback =
      std::function<bool(const std::vector<uint8_t>& data)>;

    HandleDataCallback handle_data_cb;

    size_t session_id;
    ringbuffer::WriterPtr to_host;

  public:
    ClientEndpoint(
      size_t session_id, ringbuffer::AbstractWriterFactory& writer_factory) :
      session_id(session_id),
      to_host(writer_factory.create_writer_to_outside())
    {}

    virtual void send_request(const std::vector<uint8_t>& data) = 0;

    void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f)
    {
      RINGBUFFER_WRITE_MESSAGE(
        tls::tls_connect, to_host, session_id, hostname, service);
      handle_data_cb = f;
    }
  };
}
