// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"

namespace ccf
{
  // Session wrapper used when an interface is over its soft session limit.
  //
  // It sends a single 503 response explaining that the service is busy, then
  // closes the connection. It is templated on the concrete server session type
  // (HTTPServerSession / HTTP2ServerSession) so it reuses that session's
  // response machinery.
  template <typename Base>
  class NoMoreSessionsImpl : public Base
  {
  public:
    template <typename... Ts>
    NoMoreSessionsImpl(Ts&&... ts) : Base(std::forward<Ts>(ts)...)
    {}

    void handle_incoming_data_thread(std::vector<uint8_t>&& /*data*/) override
    {
      // The transport already terminated TLS, so we can respond immediately.
      Base::send_odata_error_response(ccf::ErrorDetails{
        HTTP_STATUS_SERVICE_UNAVAILABLE,
        ccf::errors::SessionCapExhausted,
        "Service is currently busy and unable to serve new connections"});

      Base::close_session();
    }
  };
}
