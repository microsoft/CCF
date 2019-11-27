// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclavetypes.h"
#include "tls/msg_types.h"

namespace enclave
{
  class ClientEndpoint
  {
  protected:
    using HandleDataCallback =
      std::function<bool(const std::vector<uint8_t>& data)>;

    HandleDataCallback handle_data_cb;

  public:
    virtual ringbuffer::AbstractWriter* get_to_host() = 0;
    virtual size_t get_session_id() = 0;

    virtual void send_request(
      const std::string& path, const std::vector<uint8_t>& data) = 0;

    void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f)
    {
      RINGBUFFER_WRITE_MESSAGE(
        tls::tls_connect, get_to_host(), get_session_id(), hostname, service);
      handle_data_cb = f;
    }
  };
}
