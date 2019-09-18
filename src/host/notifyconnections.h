// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "tcp.h"

#include <curl/curl.h>

namespace asynchost
{
  class NotifyConnections
  {
  private:
    std::string listen_address;

  public:
    NotifyConnections(const std::string& host, const std::string& service)
    {
      if (!host.empty())
      {
        listen_address = fmt::format("{}:{}", host, service);
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

          CURL* curl = curl_easy_init();
          CURLcode res;
          if (curl)
          {
            std::string s((char const*)data, size);
            curl_easy_setopt(curl, CURLOPT_URL, listen_address.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s.c_str());

            res = curl_easy_perform(curl);
            /* Check for errors */
            if (res != CURLE_OK)
            {
              LOG_FAIL_FMT(
                "curl_easy_perform() failed: {}", curl_easy_strerror(res));
            }

            /* always cleanup */
            curl_easy_cleanup(curl);
          }
          else
          {
            LOG_FAIL_FMT("curl_easy_init failed");
          }
        });
    }
  };
}
