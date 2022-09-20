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
  {
  private:
    std::shared_ptr<RPCSessions> rpcsessions;

  public:
    QuoteEndorsementsClient(const std::shared_ptr<RPCSessions>& rpcsessions_) :
      rpcsessions(rpcsessions_){};

    void fetch_endorsements(
      const pal::EndorsementEndpointConfiguration& config,
      QuoteEndorsementsFetchedCallback cb)
    {
      // TODO: Do we need to verify server endorsements here?
      auto unauthenticated_client =
        rpcsessions->create_client(std::make_shared<tls::Cert>(
          nullptr, std::nullopt, std::nullopt, std::nullopt, false));

      unauthenticated_client->connect(
        config.host,
        config.port,
        [cb](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          if (status != HTTP_STATUS_OK)
          {
            LOG_FAIL_FMT(
              "Error fetching endorsements for attestation report: {}", status);
          }

          cb(std::move(data));
        },
        [](const std::string& error_msg) {
          // TODO: On TLS error, shutdown node
        });

      http::Request r(config.uri, HTTP_GET);
      for (auto const& [k, v] : config.params)
      {
        r.set_query_param(k, v);
      }
      r.set_header(http::headers::HOST, config.host);
      unauthenticated_client->send_request(r);
      LOG_INFO_FMT(
        "Fetching endorsements for attestation report at {}", config.host);
    }
  };
}