// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "tcp.h"

namespace asynchost
{
  class NotifyConnections
  {
  private:
    TCP notify_client;
    bool is_setup = false;

    class ClientBehaviour : public TCPBehaviour
    {
    private:
      NotifyConnections& parent;

    public:
      ClientBehaviour(NotifyConnections& parent) : parent(parent) {}

      void on_resolve_failed()
      {
        LOG_DEBUG << "notify client resolve failed " << std::endl;
        reconnect();
      }

      void on_connect_failed()
      {
        LOG_DEBUG << "notify client connect failed " << std::endl;
        reconnect();
      }

      void on_disconnect()
      {
        LOG_DEBUG << "notify client disconnect " << std::endl;
        reconnect();
      }

      void reconnect()
      {
        parent.notify_client->reconnect();
      }
    };

  public:
    NotifyConnections(const std::string& host, const std::string& service)
    {
      if (!host.empty())
      {
        LOG_INFO << "Notifications client connecting to: " << host << ":"
                 << service << std::endl;

        notify_client->set_behaviour(std::make_unique<ClientBehaviour>(*this));
        if (!notify_client->connect(host, service))
        {
          LOG_FATAL << "Notifications client failed initial connect"
                    << std::endl;
        }
        is_setup = true;
      }
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        AdminMessage::notification,
        [this](const uint8_t* data, size_t size) {
          auto [msg] =
            ringbuffer::read_message<AdminMessage::notification>(data, size);

          if (is_setup)
            notify_client->write(msg.size(), msg.data());
        });
    }
  };
}
