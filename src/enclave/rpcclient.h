// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclavetypes.h"
#include "http.h"
#include "tlsframedendpoint.h"

namespace enclave
{
#ifdef HTTP
  using ClientEndpoint = HTTPEndpoint<http::RequestHeaderEmitter>;
#else
  using ClientEndpoint = FramedTLSEndpoint;
#endif

  class RPCClient : public ClientEndpoint
  {
    using HandleDataCallback =
      std::function<bool(const std::vector<uint8_t>& data)>;

  private:
    HandleDataCallback handle_data_cb;

  public:
    RPCClient(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      ClientEndpoint(session_id, writer_factory, move(ctx))
    {}

    void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f)
    {
      RINGBUFFER_WRITE_MESSAGE(
        tls::tls_connect, to_host, session_id, hostname, service);
      handle_data_cb = f;
    }

    bool handle_data(const std::vector<uint8_t>& data) override
    {
      auto rc = handle_data_cb(data);

      close();
      return rc;
    }
  };
}
