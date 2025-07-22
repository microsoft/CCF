// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation.h"
#include "enclave/rpc_sessions.h"
#include "http/curl.h"

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
    static constexpr size_t server_connection_timeout_s = 3;

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

    std::string get_formatted_query(
      const std::map<std::string, std::string> params) const
    {
      std::string formatted_query;
      bool first = true;
      for (const auto& it : params)
      {
        formatted_query +=
          fmt::format("{}{}={}", (first ? '?' : '&'), it.first, it.second);
        first = false;
      }
      return formatted_query;
    }

    void fetch(const Server& server)
    {
      auto request_id = ++last_submitted_request_id;
      auto endpoint = server.front();

      auto request = std::make_unique<curl::CurlRequest>();

      // set curl get
      CHECK_CURL_EASY_SETOPT(request->get_easy_handle(), CURLOPT_HTTPGET, 1L);

      request->url = fmt::format(
        "{}://{}:{}{}{}",
        endpoint.tls ? "https" : "http",
        endpoint.host,
        endpoint.port,
        endpoint.uri,
        get_formatted_query(endpoint.params));

      if (endpoint.tls)
      {
        // Note: server CA is not checked here as this client is not sending
        // private data. If the server was malicious and the certificate chain
        // was bogus, the verification of the endorsement of the quote would
        // fail anyway.
        CHECK_CURL_EASY_SETOPT(
          request->get_easy_handle(), CURLOPT_SSL_VERIFYHOST, 0L);
        CHECK_CURL_EASY_SETOPT(
          request->get_easy_handle(), CURLOPT_SSL_VERIFYPEER, 0L);
        CHECK_CURL_EASY_SETOPT(
          request->get_easy_handle(), CURLOPT_SSL_VERIFYSTATUS, 0L);
      }

      for (auto const& [k, v] : endpoint.headers)
      {
        request->set_header(k, v);
      }
      request->set_header(http::headers::HOST, endpoint.host);

      request->set_response_callback([this, server, endpoint](
                                       curl::CurlRequest& request) {
        std::lock_guard<ccf::pal::Mutex> guard(this->lock);
        auto* response = request.response.get();

        if (response->status_code == HTTP_STATUS_OK)
        {
          LOG_INFO_FMT(
            "Successfully retrieved endorsements for attestation report: "
            "{} bytes",
            response->buffer.size());

          handle_success_response(std::move(response->buffer), endpoint);
          return;
        }

        LOG_DEBUG_FMT(
          "Error fetching endorsements for attestation report: {}",
          response->status_code);
        if (response->status_code == HTTP_STATUS_TOO_MANY_REQUESTS)
        {
          constexpr size_t default_retry_after_s = 3;
          size_t retry_after_s = default_retry_after_s;
          auto h = response->headers.find(http::headers::RETRY_AFTER);
          if (h != response->headers.end())
          {
            const auto& retry_after_value = h->second;
            // If value is invalid, retry_after_s is unchanged
            std::from_chars(
              retry_after_value.data(),
              retry_after_value.data() + retry_after_value.size(),
              retry_after_s);
          }

          auto msg =
            std::make_unique<::threading::Tmsg<QuoteEndorsementsClientMsg>>(
              [](std::unique_ptr<::threading::Tmsg<QuoteEndorsementsClientMsg>>
                   msg) { msg->data.self->fetch(msg->data.server); },
              shared_from_this(),
              server);

          LOG_INFO_FMT(
            "{} endorsements endpoint had too many requests. Retrying "
            "in {}s",
            endpoint,
            retry_after_s);

          ::threading::ThreadMessaging::instance().add_task_after(
            std::move(msg), std::chrono::milliseconds(retry_after_s * 1000));
        }
        return;
      });

      // Start watchdog to send request on new server if it is unresponsive
      auto msg = std::make_unique<
        ::threading::Tmsg<QuoteEndorsementsClientTimeoutMsg>>(
        [](std::unique_ptr<::threading::Tmsg<QuoteEndorsementsClientTimeoutMsg>>
             msg) {
          std::lock_guard<ccf::pal::Mutex> guard(msg->data.self->lock);
          if (msg->data.self->has_completed)
          {
            return;
          }
          if (msg->data.request_id >= msg->data.self->last_submitted_request_id)
          {
            auto& servers = msg->data.self->config.servers;
            // Should always contain at least one server,
            // installed by ccf::pal::make_endorsement_endpoint_configuration()
            if (servers.empty())
            {
              throw std::logic_error(
                "No server specified to fetch endorsements");
            }

            msg->data.self->server_retries_count++;
            if (
              msg->data.self->server_retries_count >=
              max_retries_count(servers.front()))
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
                throw ccf::pal::AttestationCollateralFetchingTimeout(
                  "Timed out fetching attestation endorsements from all "
                  "configured servers");
                return;
              }
            }

            msg->data.self->fetch(servers.front());
          }
        },
        shared_from_this(),
        endpoint,
        request_id);

      ::threading::ThreadMessaging::instance().add_task_after(
        std::move(msg),
        std::chrono::milliseconds(server_connection_timeout_s * 1000));

      LOG_INFO_FMT(
        "Fetching endorsements for attestation report at {}", request->url);

      curl::CurlmLibuvContextSingleton::get_instance_unsafe()
        ->curlm()
        .attach_curl_request(request);
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