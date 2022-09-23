// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation.h"
#include "ds/state_machine.h"
#include "enclave/rpc_sessions.h"

namespace ccf
{
  using QuoteEndorsementsFetchedCallback =
    std::function<void(std::vector<uint8_t>&& endorsements)>;

  // Resilient client to fetch attestation report endorsement certificate.
  class QuoteEndorsementsClient
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

  public:
    QuoteEndorsementsClient(const std::shared_ptr<RPCSessions>& rpcsessions_) :
      rpcsessions(rpcsessions_),
      sm("QuoteEndorsementsClient", FetchState::Uninitialised){};

    void fetch_endorsements(
      const pal::EndorsementEndpointsConfiguration& config_,
      QuoteEndorsementsFetchedCallback cb)
    {
      done_cb = cb;
      config = config_;

      if (config.endpoints.empty())
      {
        throw std::logic_error("No endpoint specified to fetch endorsements");
      }

      auto& next_endpoint = config.endpoints.front();

      auto c = create_unauthenticated_client();
      c->connect(
        next_endpoint.host,
        next_endpoint.port,
        [this, cb](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          if (status != HTTP_STATUS_OK)
          {
            LOG_FAIL_FMT(
              "Error fetching endorsements for attestation report: {}", status);
          }

          LOG_INFO_FMT(
            "Successfully retrieved endorsements for attestation report: {} "
            "bytes",
            data.size());

          auto const& content_type_header =
            headers.find(http::headers::CONTENT_TYPE);
          std::string content_type = http::headervalues::contenttype::TEXT;
          if (content_type_header != headers.end())
          {
            content_type = content_type_header->second;
          }
          else
          {
            LOG_FAIL_FMT("No content type in response");
          }

          LOG_FAIL_FMT("Content type: {}", content_type);
          LOG_FAIL_FMT("data: {}", data);

          if (content_type == http::headervalues::contenttype::OCTET_STREAM)
          {
            // If endpoint returns octet-stream content, assume that response is
            // DER-encoded certificate
            auto pem = crypto::cert_der_to_pem(data);
            auto raw = pem.raw();
            LOG_FAIL_FMT("pem: {}", pem.str());
            endorsements.insert(endorsements.end(), raw.begin(), raw.end());
          }
          else
          {
            // Otherwise, assume that is PEM
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
        },
        [](const std::string& error_msg) {
          // TLS errors should be handled here
        });

      http::Request r(next_endpoint.uri, HTTP_GET);
      for (auto const& [k, v] : next_endpoint.params)
      {
        r.set_query_param(k, v);
      }
      r.set_header(http::headers::HOST, next_endpoint.host);

      LOG_INFO_FMT(
        "Fetching endorsements for attestation report at https://{}{}{}",
        next_endpoint.host,
        r.get_path(),
        r.get_formatted_query());
      c->send_request(r);
    }
  };
}