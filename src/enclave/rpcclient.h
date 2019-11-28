// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "clientendpoint.h"
#include "framedtlsendpoint.h"

namespace enclave
{
  class RPCClient : public FramedTLSEndpoint, public ClientEndpoint
  {
  public:
    RPCClient(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      FramedTLSEndpoint(session_id, writer_factory, move(ctx)),
      ClientEndpoint(session_id, writer_factory)
    {}

    void send_request(
      const std::string& path, const std::vector<uint8_t>& data) override
    {
      send(data);
    }

    bool handle_data(const std::vector<uint8_t>& data) override
    {
      auto rc = handle_data_cb(data);

      close();
      return rc;
    }
  };
}
