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
    ds::StateMachine<FetchState> sm;

  public:
    QuoteEndorsementsClient(const std::shared_ptr<RPCSessions>& rpcsessions_) :
      rpcsessions(rpcsessions_),
      sm("QuoteEndorsementsClient", FetchState::Uninitialised){};

    void fetch_endorsements(
      const pal::EndorsementEndpointConfiguration& config,
      QuoteEndorsementsFetchedCallback cb)
    {
      sm.advance(FetchState::FetchingVcek);

      // Note: server CA is not checked here as this client is not sending
      // private data. If the server was malicious and the certificate chain was
      // bogus, the verification of the endorsement of the quote would fail
      // anyway.
      auto unauthenticated_client =
        rpcsessions->create_client(std::make_shared<tls::Cert>(
          nullptr, std::nullopt, std::nullopt, std::nullopt, false));

      unauthenticated_client->connect(
        config.endpoints.front().host,
        config.endpoints.front().port,
        [this, cb](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          sm.expect(FetchState::FetchingVcek);
          if (status != HTTP_STATUS_OK)
          {
            LOG_FAIL_FMT(
              "Error fetching endorsements for attestation report: {}", status);
          }

          LOG_INFO_FMT(
            "Successfully retrieved endorsements for attestation report: {} "
            "bytes",
            data.size());

          // cb(std::move(data));
          sm.advance(FetchState::Done);
        },
        [](const std::string& error_msg) {
          // TLS errors should be handled here
        });

      http::Request r(config.endpoints.front().uri, HTTP_GET);
      for (auto const& [k, v] : config.endpoints.front().params)
      {
        r.set_query_param(k, v);
      }
      r.set_header(http::headers::HOST, config.endpoints.front().host);

      LOG_INFO_FMT(
        "Fetching endorsements for attestation report at https://{}{}{}",
        config.endpoints.front().host,
        r.get_path(),
        r.get_formatted_query());
      unauthenticated_client->send_request(r);
    }
  };
}