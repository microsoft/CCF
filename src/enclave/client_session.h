// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http/http_builder.h"
#include "tcp/msg_types.h"

#include <functional>

namespace ccf
{
  class ClientSession
  {
  public:
    virtual ~ClientSession() = default;

    using HandleDataCallback = std::function<void(
      ccf::http_status status,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body)>;

    using HandleErrorCallback =
      std::function<void(const std::string& error_msg)>;

    // Opens an outbound transport connection for `id` to host:service. Supplied
    // by the connection manager when it creates the client session.
    using ConnectCallback = std::function<void(
      int64_t id, const std::string& host, const std::string& service)>;

  protected:
    HandleDataCallback handle_data_cb;
    HandleErrorCallback handle_error_cb;

  private:
    int64_t client_session_id;
    ConnectCallback connect_cb;

  public:
    ClientSession(int64_t client_session_id_, ConnectCallback connect_cb_) :
      client_session_id(client_session_id_),
      connect_cb(std::move(connect_cb_))
    {}

    virtual void send_request(::http::Request&& request) = 0;

    virtual void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f,
      const HandleErrorCallback e = nullptr)
    {
      if (connect_cb)
      {
        connect_cb(client_session_id, hostname, service);
      }
      handle_data_cb = f;
      handle_error_cb = e;
    }
  };
}
