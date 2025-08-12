// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation.h"
#include "enclave/rpc_sessions.h"

namespace ccf
{
  using QuoteEndorsementsFetchedCallback =
    std::function<void(std::vector<uint8_t>&& endorsements)>;
  using Server = pal::snp::EndorsementEndpointsConfiguration::Server;

  static inline size_t max_retries_count(const Server& server)
  {
    // Each server should contain at least one endpoint definition
    if (server.empty())
    {
      throw std::logic_error(
        "No endpoints defined in SNP attestation collateral server");
    }

    // If multiple endpoints are defined, the max_retries_count of the first
    // if the maximum number of retries for the server.
    return server.front().max_retries_count;
  }

  // Resilient client to fetch attestation report endorsement certificate.
  class QuoteEndorsementsClient
    : public std::enable_shared_from_this<QuoteEndorsementsClient>
  {
  private:
    using EndpointInfo =
      pal::snp::EndorsementEndpointsConfiguration::EndpointInfo;

    // Resend request after this interval if no response was received from
    // remote server
    static constexpr std::chrono::seconds server_connection_timeout =
      std::chrono::seconds(3);

    std::shared_ptr<RPCSessions> rpcsessions;

    pal::snp::EndorsementEndpointsConfiguration config;
    QuoteEndorsementsFetchedCallback done_cb;

    std::vector<uint8_t> endorsements_pem;

    ccf::pal::Mutex lock;

    // Uniquely identify each received request. We assume that this client sends
    // requests in series, after receiving the response to each one or after a
    // long timeout.
    size_t last_submitted_request_id = 0;
    bool has_completed = false;
    size_t server_retries_count = 0;

    std::shared_ptr<ClientSession> create_unauthenticated_client()
    {
      // Note: server CA is not checked here as this client is not sending
      // private data. If the server was malicious and the certificate chain was
      // bogus, the verification of the endorsement of the quote would fail
      // anyway.
      return rpcsessions->create_client(std::make_shared<::tls::Cert>(
        nullptr, std::nullopt, std::nullopt, std::nullopt, false));
    }

    std::shared_ptr<ClientSession> create_unencrypted_client()
    {
      return rpcsessions->create_unencrypted_client();
    }

    void send_request(
      const std::shared_ptr<ClientSession>& client,
      const EndpointInfo& endpoint)
    {
      auto request_id = ++last_submitted_request_id;
      {
        ::http::Request r(endpoint.uri, HTTP_GET);
        for (auto const& [k, v] : endpoint.params)
        {
          r.set_query_param(k, v);
        }
        for (auto const& [k, v] : endpoint.headers)
        {
          r.set_header(k, v);
        }
        r.set_header(http::headers::HOST, endpoint.host);

        LOG_INFO_FMT(
          "Fetching endorsements for attestation report at {}{}{}",
          endpoint,
          r.get_path(),
          r.get_formatted_query());
        client->send_request(std::move(r));
      }

      // Start watchdog to send request on new server if it is unresponsive
      auto self = shared_from_this();
      ccf::tasks::add_delayed_task(
        ccf::tasks::make_basic_task([self, endpoint, request_id]() {
          std::lock_guard<ccf::pal::Mutex> guard(self->lock);
          if (self->has_completed)
          {
            return;
          }
          if (request_id >= self->last_submitted_request_id)
          {
            auto& servers = self->config.servers;
            // Should always contain at least one server,
            // installed by ccf::pal::make_endorsement_endpoint_configuration()
            if (servers.empty())
            {
              throw std::logic_error(
                "No server specified to fetch endorsements");
            }

            self->server_retries_count++;
            if (
              self->server_retries_count >= max_retries_count(servers.front()))
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
                  "{} after {} attempts",
                  server.front().host,
                  server.front().max_retries_count);
                // TODO: Do we have a test for this? How do we handle exceptions
                // in tasks?
                throw ccf::pal::AttestationCollateralFetchingTimeout(
                  "Timed out fetching attestation endorsements from all "
                  "configured servers");
                return;
              }
            }

            self->fetch(servers.front());
          }
        }),
        server_connection_timeout);
    }

    void handle_success_response(
      std::vector<uint8_t>&& data, const EndpointInfo& response_endpoint)
    {
      // We may receive a response to an in-flight request after having
      // fetched all endorsements
      auto& server = config.servers.front();
      if (server.empty())
      {
        return;
      }
      auto endpoint = server.front();
      if (has_completed || response_endpoint != endpoint)
      {
        return;
      }

      if (response_endpoint.response_is_der)
      {
        auto raw = ccf::crypto::cert_der_to_pem(data).raw();
        endorsements_pem.insert(endorsements_pem.end(), raw.begin(), raw.end());
      }
      else if (response_endpoint.response_is_thim_json)
      {
        auto j = nlohmann::json::parse(data);
        auto vcekCert = j.at("vcekCert").get<std::string>();
        auto certificateChain = j.at("certificateChain").get<std::string>();
        endorsements_pem.insert(
          endorsements_pem.end(), vcekCert.begin(), vcekCert.end());
        endorsements_pem.insert(
          endorsements_pem.end(),
          certificateChain.begin(),
          certificateChain.end());
      }
      else
      {
        endorsements_pem.insert(
          endorsements_pem.end(), data.begin(), data.end());
      }

      server.pop_front();
      if (server.empty())
      {
        LOG_INFO_FMT("Complete endorsement chain successfully retrieved");
        LOG_INFO_FMT(
          "{}", std::string(endorsements_pem.begin(), endorsements_pem.end()));
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
      auto endpoint = server.front();

      auto c = endpoint.tls ? create_unauthenticated_client() :
                              create_unencrypted_client();
      c->connect(
        endpoint.host,
        endpoint.port,
        [this, server, endpoint](
          ccf::http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          std::lock_guard<ccf::pal::Mutex> guard(this->lock);

          if (status == HTTP_STATUS_OK)
          {
            LOG_INFO_FMT(
              "Successfully retrieved endorsements for attestation report: "
              "{} bytes",
              data.size());

            handle_success_response(std::move(data), endpoint);
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
            const std::chrono::seconds retry_after(retry_after_s);

            LOG_INFO_FMT(
              "{} endorsements endpoint had too many requests. Retrying "
              "in {}s",
              endpoint,
              retry_after_s);

            auto self = shared_from_this();
            ccf::tasks::add_delayed_task(
              ccf::tasks::make_basic_task(
                [self, server]() { self->fetch(server); }),
              retry_after);
          }
          return;
        },
        [endpoint](const std::string& error_msg) {
          LOG_FAIL_FMT(
            "TLS error when connecting to quote endorsements endpoint {}: {}",
            endpoint,
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
      done_cb(cb) {};

    void fetch_endorsements()
    {
      std::lock_guard<ccf::pal::Mutex> guard(this->lock);
      auto const& server = config.servers.front();
      if (server.empty())
      {
        throw std::logic_error("No server specified to fetch endorsements");
      }
      fetch(server);
    }
  };
}