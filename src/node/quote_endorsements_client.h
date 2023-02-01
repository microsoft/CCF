// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation.h"
#include "enclave/rpc_sessions.h"

namespace ccf
{
  using QuoteEndorsementsFetchedCallback =
    std::function<void(std::vector<uint8_t>&& endorsements)>;

  // Resilient client to fetch attestation report endorsement certificate.
  class QuoteEndorsementsClient
    : public std::enable_shared_from_this<QuoteEndorsementsClient>
  {
  private:
    using EndpointInfo =
      pal::snp::EndorsementEndpointsConfiguration::EndpointInfo;
    using Server = pal::snp::EndorsementEndpointsConfiguration::Server;

    // Resend request after this interval if no response was received from
    // remote server
    static constexpr size_t server_connection_timeout_s = 3;

    // Maximum number of retries per remote server before giving up and moving
    // on to the next server.
    static constexpr size_t max_server_retries_count = 3;

    std::shared_ptr<RPCSessions> rpcsessions;

    pal::snp::EndorsementEndpointsConfiguration config;
    QuoteEndorsementsFetchedCallback done_cb;

    std::vector<uint8_t> endorsements_pem;

    // Uniquely identify each received request. We assume that this client sends
    // requests in series, after receiving the response to each one or after a
    // long timeout.
    size_t last_received_request_id = 0;
    bool has_completed = false;
    size_t server_retries_count = 0;

    struct QuoteEndorsementsClientMsg
    {
      QuoteEndorsementsClientMsg(
        const std::shared_ptr<QuoteEndorsementsClient>& self_,
        const Server& server_) :
        self(self_),
        server(server_)
      {}

      std::shared_ptr<QuoteEndorsementsClient> self;
      Server server;
    };

    struct QuoteEndorsementsClientTimeoutMsg
    {
      QuoteEndorsementsClientTimeoutMsg(
        const std::shared_ptr<QuoteEndorsementsClient>& self_,
        const EndpointInfo& endpoint_,
        size_t request_id_) :
        self(self_),
        endpoint(endpoint_),
        request_id(request_id_)
      {}

      std::shared_ptr<QuoteEndorsementsClient> self;
      EndpointInfo endpoint;
      size_t request_id;
    };

    std::shared_ptr<ClientSession> create_unauthenticated_client()
    {
      // Note: server CA is not checked here as this client is not sending
      // private data. If the server was malicious and the certificate chain was
      // bogus, the verification of the endorsement of the quote would fail
      // anyway.
      return rpcsessions->create_client(std::make_shared<tls::Cert>(
        nullptr, std::nullopt, std::nullopt, std::nullopt, false));
    }

    void send_request(
      const std::shared_ptr<ClientSession>& client,
      const EndpointInfo& endpoint)
    {
      {
        http::Request r(endpoint.uri, HTTP_GET);
        for (auto const& [k, v] : endpoint.params)
        {
          r.set_query_param(k, v);
        }
        r.set_header(http::headers::HOST, endpoint.host);

        LOG_INFO_FMT(
          "Fetching endorsements for attestation report at https://{}{}{}",
          endpoint.host,
          r.get_path(),
          r.get_formatted_query());
        client->send_request(std::move(r));
      }

      // Start watchdog to send request on new server if it is unresponsive
      auto msg = std::make_unique<
        threading::Tmsg<QuoteEndorsementsClientTimeoutMsg>>(
        [](std::unique_ptr<threading::Tmsg<QuoteEndorsementsClientTimeoutMsg>>
             msg) {
          if (msg->data.self->has_completed)
          {
            return;
          }
          if (msg->data.request_id >= msg->data.self->last_received_request_id)
          {
            LOG_FAIL_FMT(
              "Timed out reaching endorsement server {}",
              msg->data.endpoint.host);

            auto& servers = msg->data.self->config.servers;
            msg->data.self->server_retries_count++;
            if (
              msg->data.self->server_retries_count >= max_server_retries_count)
            {
              if (servers.size() > 1)
              {
                // Move on to next server if we have passed max retries count
                servers.pop_front();
              }
              else
              {
                auto& server = servers.front();
                LOG_FAIL_FMT(
                  "Giving up retrying fetching attestation endorsements from "
                  "{} after {} attempts ",
                  server.front().host,
                  max_server_retries_count);
                return;
              }
            }

            msg->data.self->fetch(servers.front());
          }
        },
        shared_from_this(),
        endpoint,
        last_received_request_id);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg),
        std::chrono::milliseconds(server_connection_timeout_s * 1000));
    }

    void handle_success_response(std::vector<uint8_t>&& data, bool is_der)
    {
      if (has_completed)
      {
        // We may receive a response to an in-flight request after having
        // fetched all endorsements
        return;
      }

      if (is_der)
      {
        auto raw = crypto::cert_der_to_pem(data).raw();
        endorsements_pem.insert(endorsements_pem.end(), raw.begin(), raw.end());
      }
      else
      {
        endorsements_pem.insert(
          endorsements_pem.end(), data.begin(), data.end());
      }

      auto& server = config.servers.front();
      server.pop_front();
      if (server.empty())
      {
        LOG_INFO_FMT("Complete endorsement chain successfully retrieved");
        has_completed = true;
        done_cb(std::move(endorsements_pem));
      }
      else
      {
        fetch(server);
      }
    }

    void fetch(const Server& server)
    {
      auto& endpoint = server.front();

      auto c = create_unauthenticated_client();
      c->connect(
        endpoint.host,
        endpoint.port,
        [this, server](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          last_received_request_id++;
          auto& endpoint = server.front();

          if (status == HTTP_STATUS_OK)
          {
            LOG_INFO_FMT(
              "Successfully retrieved endorsements for attestation report: "
              "{} bytes",
              data.size());

            handle_success_response(std::move(data), endpoint.response_is_der);
            return;
          }

          LOG_DEBUG_FMT(
            "Error fetching endorsements for attestation report: {}", status);
          if (status == HTTP_STATUS_TOO_MANY_REQUESTS)
          {
            constexpr size_t default_retry_after_s = 3;
            size_t retry_after_s = default_retry_after_s;
            auto h = headers.find(http::headers::RETRY_AFTER);
            if (h != headers.end())
            {
              const auto& retry_after_value = h->second;
              // If value is invalid, retry_after_s is unchanged
              std::from_chars(
                retry_after_value.data(),
                retry_after_value.data() + retry_after_value.size(),
                retry_after_s);
            }

            auto msg =
              std::make_unique<threading::Tmsg<QuoteEndorsementsClientMsg>>(
                [](std::unique_ptr<threading::Tmsg<QuoteEndorsementsClientMsg>>
                     msg) { msg->data.self->fetch(msg->data.server); },
                shared_from_this(),
                server);

            LOG_INFO_FMT(
              "{} endorsements endpoint had too many requests. Retrying "
              "in {}s",
              endpoint.host,
              retry_after_s);

            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), std::chrono::milliseconds(retry_after_s * 1000));
          }
          return;
        },
        [host = endpoint.host](const std::string& error_msg) {
          LOG_FAIL_FMT(
            "TLS error when connecting to quote endorsements endpoint {}: {}",
            host,
            error_msg);
        });
      send_request(c, endpoint);
    }

  public:
    QuoteEndorsementsClient(
      const std::shared_ptr<RPCSessions>& rpcsessions_,
      const pal::snp::EndorsementEndpointsConfiguration& config_,
      QuoteEndorsementsFetchedCallback cb) :
      rpcsessions(rpcsessions_),
      config(config_),
      done_cb(cb){};

    void fetch_endorsements()
    {
      auto const& server = config.servers.front();
      if (server.empty())
      {
        throw std::logic_error("No server specified to fetch endorsements");
      }
      fetch(server);
    }
  };
}