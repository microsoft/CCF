// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "enclave/tls_session.h"

namespace ccf
{
  // Session wrapper used when an interface is over its soft session limit.
  //
  // It completes the TLS handshake far enough to send a single 503 response
  // explaining that the service is busy, then closes the connection. It is
  // templated on the concrete server session type (HTTPServerSession /
  // HTTP2ServerSession) so it reuses that session's TLS plumbing and response
  // machinery.
  //
  // Previously nested inside RPCSessions; pulled out so both the legacy
  // RPCSessions and the new RPCConnectionManager can share it.
  template <typename Base>
  class NoMoreSessionsImpl : public Base
  {
  public:
    template <typename... Ts>
    NoMoreSessionsImpl(Ts&&... ts) : Base(std::forward<Ts>(ts)...)
    {}

    void handle_incoming_data_thread(std::vector<uint8_t>&& data) override
    {
      Base::tls_io->recv_buffered(data.data(), data.size());

      if (Base::tls_io->get_status() == ccf::SessionStatus::ready)
      {
        // Send response describing soft session limit
        Base::send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::SessionCapExhausted,
          "Service is currently busy and unable to serve new connections"});

        // Close connection
        Base::tls_io->close();
      }
    }
  };
}
