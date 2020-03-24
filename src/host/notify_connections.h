// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "every_io.h"
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

    // To ensure we cleanup all open handles, keep track of them locally
    std::set<CURL*> easy_handles;

    void send_notification(const std::vector<uint8_t>& body)
    {
      if (multi_handle)
      {
        CURL* curl = curl_easy_init();
        easy_handles.insert(curl);

        curl_easy_setopt(curl, CURLOPT_URL, notify_destination.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, body.data());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_multi_add_handle(multi_handle, curl);
      }
    };

  public:
    NotifyConnectionsImpl(
      messaging::Dispatcher<ringbuffer::Message>& disp,
      const std::string& host,
      const std::string& service)
    {
      auto init_res = curl_global_init(CURL_GLOBAL_ALL);
      if (init_res != 0)
      {
        throw std::logic_error(fmt::format(
          "libcurl global initialisation failed: {}",
          curl_easy_strerror(init_res)));
      }

      if (!host.empty())
      {
        notify_destination = fmt::format("{}:{}", host, service);

        multi_handle = curl_multi_init();
        if (multi_handle == nullptr)
        {
          LOG_FAIL_FMT("Failed to initialised curl multi handle");
        }

        headers = curl_slist_append(headers, "Content-Type: application/json");
      }

      register_message_handlers(disp);
    }

    ~NotifyConnectionsImpl()
    {
      for (auto easy_handle : easy_handles)
      {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
      }
      curl_multi_cleanup(multi_handle);
      easy_handles.clear();
    }

    void every()
    {
      int still_running = 0;
      curl_multi_perform(multi_handle, &still_running);

      CURLMsg* message;
      int pending;
      while ((message = curl_multi_info_read(multi_handle, &pending)))
      {
        switch (message->msg)
        {
          case CURLMSG_DONE:
          {
            CURL* easy_handle = message->easy_handle;

            long response_code;
            auto res = curl_easy_getinfo(
              easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
            if (res == CURLE_OK)
            {
              LOG_DEBUG_FMT(
                "Notification completed with response code {}", response_code);
            }
            else
            {
              LOG_FAIL_FMT(
                "Unable to retrieve response code for completed notification: "
                "{}",
                curl_easy_strerror(res));
            }

            // Cleanup completed handles - NB: message contents are invalidated!
            auto mres = curl_multi_remove_handle(multi_handle, easy_handle);
            if (mres != CURLM_OK)
            {
              LOG_FAIL_FMT(
                "Failed to remove curl handle from multi-handle: {}",
                curl_multi_strerror(mres));
            }

            curl_easy_cleanup(easy_handle);
            easy_handles.erase(easy_handle);
            break;
          }
          default:
          {
            LOG_FAIL_FMT(
              "Unhandled case while processing curl info message: {}",
              message->msg);
            break;
          }
        }
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

          send_notification(msg);
        });
    }
  };

  using NotifyConnections = proxy_ptr<EveryIO<NotifyConnectionsImpl>>;
}
