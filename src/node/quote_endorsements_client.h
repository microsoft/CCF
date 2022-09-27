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
    std::shared_ptr<RPCSessions> rpcsessions;

    enum class FetchState
    {
      Uninitialised = 0,
      FetchingVcek,
      Fetching,
      Done
    };
    ds::StateMachine<FetchState> sm; // TODO: Do we really need this?

    pal::EndorsementEndpointsConfiguration config;
    QuoteEndorsementsFetchedCallback done_cb;

    std::vector<uint8_t> endorsements;

    std::shared_ptr<ClientEndpoint> create_unauthenticated_client()
    {
      // Note: server CA is not checked here as this client is not sending
      // private data. If the server was malicious and the certificate chain was
      // bogus, the verification of the endorsement of the quote would fail
      // anyway.
      return rpcsessions->create_client(std::make_shared<tls::Cert>(
        nullptr, std::nullopt, std::nullopt, std::nullopt, false));
    }

    void send_request(
      const std::shared_ptr<ClientEndpoint>& client,
      const pal::EndorsementEndpointsConfiguration::EndpointInfo& endpoint)
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
      client->send_request(r);
    }

    void handle_success_response(std::vector<uint8_t>&& data, bool is_der)
    {
      if (is_der)
      {
        auto pem = crypto::cert_der_to_pem(data);
        auto raw = pem.raw();
        LOG_FAIL_FMT("pem: {}", pem.str());
        endorsements.insert(endorsements.end(), raw.begin(), raw.end());
      }
      else
      {
        // Otherwise, assume that is PEM
        LOG_FAIL_FMT("pem: {}", crypto::Pem(data).str());
        endorsements.insert(
          endorsements.end(),
          std::make_move_iterator(data.begin()),
          std::make_move_iterator(data.end()));
      }

      // TODO:
      // 0. Store first response
      // 1. Call second endpoint when first one has succeeded (AMD only)
      // 2. When done, call cb(std::move(endorsements))
      // 3. Support Azure endpoint too

      // cb(std::move(data));
      config.endpoints.pop_front();

      if (config.endpoints.empty())
      {
        LOG_INFO_FMT("Entire endorsement chain successfully retrieved");
        done_cb(std::move(endorsements));
      }
      else
      {
        fetch(config.endpoints.front());
      }
    }

    // TODO: Move to top
    struct QuoteEndorsementsClientMsg
    {
      QuoteEndorsementsClientMsg(
        const std::shared_ptr<QuoteEndorsementsClient>& self_,
        const pal::EndorsementEndpointsConfiguration::EndpointInfo& endpoint_) :
        self(self_),
        endpoint(endpoint_)
      {}

      std::shared_ptr<QuoteEndorsementsClient> self;
      pal::EndorsementEndpointsConfiguration::EndpointInfo endpoint;
    };

    void fetch(
      const pal::EndorsementEndpointsConfiguration::EndpointInfo& endpoint)
    {
      auto c = create_unauthenticated_client();
      c->connect(
        endpoint.host,
        endpoint.port,
        [this, endpoint](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          if (status != HTTP_STATUS_OK)
          {
            LOG_FAIL_FMT(
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
                  [](
                    std::unique_ptr<threading::Tmsg<QuoteEndorsementsClientMsg>>
                      msg) { msg->data.self->fetch(msg->data.endpoint); },
                  shared_from_this(),
                  endpoint);

              LOG_INFO_FMT(
                "{} endorsements server had too many requests. Retrying in {}s",
                endpoint.host,
                retry_after_s);

              threading::ThreadMessaging::thread_messaging.add_task_after(
                std::move(msg),
                std::chrono::milliseconds(retry_after_s * 1000));
            }
            return;
          }

          LOG_INFO_FMT(
            "Successfully retrieved endorsements for attestation report: {} "
            "bytes",
            data.size());

          LOG_FAIL_FMT("data: {}", data);

          handle_success_response(std::move(data), endpoint.response_is_der);
        },
        [](const std::string& error_msg) {
          // TLS errors should be handled here
        });
      send_request(c, endpoint);
    }

  public:
    QuoteEndorsementsClient(const std::shared_ptr<RPCSessions>& rpcsessions_) :
      rpcsessions(rpcsessions_),
      sm("QuoteEndorsementsClient", FetchState::Uninitialised){};

    void fetch_endorsements(
      const pal::EndorsementEndpointsConfiguration& config_,
      QuoteEndorsementsFetchedCallback cb)
    {
      // TODO: Pass these on constructor instead?
      done_cb = cb;
      config = config_;

      if (config.endpoints.empty())
      {
        throw std::logic_error("No endpoint specified to fetch endorsements");
      }

      fetch(config.endpoints.front());
    }
  };
}