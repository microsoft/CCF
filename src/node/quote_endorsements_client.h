// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation.h"
#include "enclave/rpc_sessions.h"

namespace ccf
{
  // Resilient client to fetch attestation report endorsement certificate.
  // Handles back-pressure (HTTP 429) and multiple endpoints.
  class QuoteEndorsementsClient
  {
  private:
    std::shared_ptr<RPCSessions> rpcsessions;

  public:
    QuoteEndorsementsClient(const std::shared_ptr<RPCSessions>& rpcsessions_) :
      rpcsessions(rpcsessions_){};

    void fetch_endorsements(const pal::EndorsementEndpointConfiguration& config)
    {
      // TODO: Do we need to verify server endorsements here?
      auto unauthenticated_client =
        rpcsessions->create_client(std::make_shared<tls::Cert>(
          nullptr, std::nullopt, std::nullopt, std::nullopt, false));

      unauthenticated_client->connect(
        config.host,
        config.port,
        [this](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          // TODO: On success

          LOG_FAIL_FMT("Here!: {}", status);

          if (status != HTTP_STATUS_OK)
          {
            CCF_APP_FAIL("Error: {}", status);
            // TODO: If 429, wait and retry (by creating new client)
          }

          // std::lock_guard<pal::Mutex> guard(lock);

          LOG_FAIL_FMT("Got a response: {}, [{}]", status, data.size());
          // quote_info = quote_info_;
          // quote_info.endorsements.assign(data.begin(), data.end());

          // auto code_id = EnclaveAttestationProvider::get_code_id(quote_info);
          // if (code_id.has_value())
          // {
          //   node_code_id = code_id.value();
          // }
          // else
          // {
          //   throw std::logic_error("Failed to extract code id from quote");
          // }

          // launch_node();
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
      LOG_INFO_FMT("Fetching endorsements for quote at {}", config.host);
    }
  };
}