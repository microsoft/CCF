// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "everyio.h"
#include "tcp.h"

#include <curl/curl.h>

namespace asynchost
{
  class NotifyConnectionsImpl
  {
  private:
    CURLM* multi_handle = nullptr;
    curl_slist* headers = nullptr;

    std::string notify_destination = {};

    void send_notification(const std::vector<uint8_t>& body)
    {
      if (multi_handle)
      {
        CURL* curl = curl_easy_init();

        curl_multi_add_handle(multi_handle, curl);

        curl_easy_setopt(curl, CURLOPT_URL, notify_destination.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, body.data());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      }
    };

  public:
    NotifyConnectionsImpl(
      messaging::Dispatcher<ringbuffer::Message>& disp,
      const std::string& host,
      const std::string& service)
    {
      if (!host.empty())
      {
        notify_destination = fmt::format("{}:{}", host, service);

        multi_handle = curl_multi_init();
      }

      register_message_handlers(disp);
    }

    ~NotifyConnectionsImpl()
    {
      // TODO: Remove and cleanup all remaining handles,
      curl_multi_cleanup(multi_handle);
    }

    void every()
    {
      int still_running = 0;
      curl_multi_perform(multi_handle, &still_running);

      // TODO: Get info on remaining handles, remove those which are done
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

          send_notification(msg);
        });
    }
  };

  using NotifyConnections = proxy_ptr<EveryIO<NotifyConnectionsImpl>>;
}
