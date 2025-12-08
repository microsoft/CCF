// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/http_consts.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/locking.h"
#include "http/curl.h"
#include "tasks/basic_task.h"
#include "tasks/task.h"
#include "tasks/task_system.h"

#include <curl/curl.h>

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
    static constexpr size_t server_response_timeout_s = 3;

    const pal::snp::EndorsementEndpointsConfiguration config;
    QuoteEndorsementsFetchedCallback done_cb;

    std::vector<uint8_t> endorsements_pem;

    ccf::pal::Mutex lock;

    // Iteration variables
    std::list<Server> servers;
    size_t server_retries_count = 0;
    size_t total_retries_count = 0;

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

    void handle_success_response_unsafe(std::vector<uint8_t>&& data)
    {
      auto& server = servers.front();
      if (server.empty())
      {
        return;
      }
      auto endpoint = server.front();

      if (endpoint.response_is_der)
      {
        auto raw = ccf::crypto::cert_der_to_pem(data).raw();
        endorsements_pem.insert(endorsements_pem.end(), raw.begin(), raw.end());
      }
      else if (endpoint.response_is_thim_json)
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

      // advance to the next endpoint
      server.pop_front();

      if (server.empty())
      {
        LOG_INFO_FMT("Complete endorsement chain successfully retrieved");
        LOG_INFO_FMT(
          "{}", std::string(endorsements_pem.begin(), endorsements_pem.end()));
        done_cb(std::move(endorsements_pem));
      }
      else
      {
        fetch_unsafe();
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

    void fetch()
    {
      std::lock_guard<ccf::pal::Mutex> guard(this->lock);
      fetch_unsafe();
    }

    struct HandleResponseTask : public ccf::tasks::BaseTask
    {
      std::shared_ptr<QuoteEndorsementsClient> self;
      std::unique_ptr<curl::CurlRequest> request;
      CURLcode curl_response;
      long status_code;

      HandleResponseTask(
        std::shared_ptr<QuoteEndorsementsClient> self_,
        std::unique_ptr<curl::CurlRequest>&& request_,
        CURLcode curl_response_,
        long status_code_) :
        self(self_),
        request(std::move(request_)),
        curl_response(curl_response_),
        status_code(status_code_)
      {}

      void do_task_implementation() override
      {
        std::lock_guard<ccf::pal::Mutex> guard(self->lock);

        auto* response_body = request->get_response_body();
        const auto& response_headers = request->get_response_headers();

        if (curl_response == CURLE_OK && status_code == HTTP_STATUS_OK)
        {
          LOG_INFO_FMT(
            "Successfully retrieved endorsements for attestation report: "
            "{} bytes",
            response_body->buffer.size());

          self->handle_success_response_unsafe(
            std::move(response_body->buffer));
          return;
        }

        LOG_DEBUG_FMT(
          "Error fetching endorsements for attestation report: {} ({}) {}",
          curl_easy_strerror(curl_response),
          curl_response,
          status_code);

        if (
          self->server_retries_count >=
          max_retries_count(self->servers.front()))
        {
          self->servers.pop_front();

          if (self->servers.empty())
          {
            auto servers_tried = std::accumulate(
              self->config.servers.begin(),
              self->config.servers.end(),
              std::string{},
              [](const std::string& a, const Server& b) {
                return a + (a.length() > 0 ? ", " : "") + b.front().host;
              });
            LOG_FAIL_FMT(
              "Giving up retrying fetching attestation endorsements from [{}] "
              "after {} attempts",
              servers_tried,
              self->total_retries_count);
            throw ccf::pal::AttestationCollateralFetchingTimeout(
              "Timed out fetching attestation endorsements from all "
              "configured servers");
          }

          self->server_retries_count = 0;
          self->fetch_unsafe();
        }
        else
        {
          ++self->server_retries_count;
          ++self->total_retries_count;

          const auto& endpoint = self->servers.front().front();

          constexpr size_t default_retry_after_s = 3;
          size_t retry_after_s = default_retry_after_s;
          if (
            curl_response == CURLE_OK &&
            status_code == HTTP_STATUS_TOO_MANY_REQUESTS)
          {
            auto h = response_headers.find(http::headers::RETRY_AFTER);
            if (h != response_headers.end())
            {
              const auto& retry_after_value = h->second;
              // If value is invalid, retry_after_s is unchanged
              std::from_chars(
                retry_after_value.data(),
                retry_after_value.data() + retry_after_value.size(),
                retry_after_s);
            }

            LOG_INFO_FMT(
              "{} endorsements endpoint had too many requests. Retrying "
              "in {}s",
              endpoint,
              retry_after_s);
          }
          else
          {
            LOG_INFO_FMT(
              "{} endorsements endpoint failed to respond. Retrying "
              "in {}s",
              endpoint,
              retry_after_s);
          }

          const std::chrono::seconds retry_after(retry_after_s);

          ccf::tasks::add_delayed_task(
            ccf::tasks::make_basic_task(
              [self = this->self]() { self->fetch(); }),
            retry_after);
        }
      }

      const std::string& get_name() const override
      {
        static const std::string name =
          "QuoteEndorsementsClient::HandleResponseTask";
        return name;
      }
    };

    void fetch_unsafe()
    {
      const auto& server = servers.front();
      const auto& endpoint = server.front();

      curl::UniqueCURL curl_handle;

      // Set curl get
      curl_handle.set_opt(CURLOPT_HTTPGET, 1L);
      // If the server does not respond at all within this time timeout
      curl_handle.set_opt(CURLOPT_CONNECTTIMEOUT, server_connection_timeout_s);
      // If the server does not completely response within this time timeout
      curl_handle.set_opt(CURLOPT_TIMEOUT, server_response_timeout_s);

      auto url = fmt::format(
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
        curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 0L);
        curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 0L);
        curl_handle.set_opt(CURLOPT_SSL_VERIFYSTATUS, 0L);
      }

      auto headers = ccf::curl::UniqueSlist();
      for (auto const& [k, v] : endpoint.headers)
      {
        headers.append(k, v);
      }
      headers.append(http::headers::HOST, endpoint.host);

      auto response_callback = ([self = shared_from_this()](
                                  std::unique_ptr<curl::CurlRequest>&& request,
                                  CURLcode curl_response,
                                  long status_code) {
        std::shared_ptr<HandleResponseTask> response_task =
          std::make_shared<HandleResponseTask>(
            self, std::move(request), curl_response, status_code);
        ccf::tasks::add_task(response_task);
      });

      auto request = std::make_unique<curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_GET,
        std::move(url),
        std::move(headers),
        nullptr,
        std::make_unique<ccf::curl::ResponseBody>(
          endpoint.max_client_response_size),
        std::move(response_callback));

      LOG_INFO_FMT(
        "Fetching endorsements for attestation report at {}",
        request->get_url());
      curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
        std::move(request));
    }

  public:
    QuoteEndorsementsClient(
      const pal::snp::EndorsementEndpointsConfiguration& config_,
      QuoteEndorsementsFetchedCallback cb) :
      config(config_),
      done_cb(cb) {};

    void fetch_endorsements()
    {
      std::lock_guard<ccf::pal::Mutex> guard(this->lock);
      servers = std::list<Server>(config.servers);
      server_retries_count = 0;

      fetch_unsafe();
    }
  };
}