// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "attestation.h"
#include "http_client.h"
#include "ravl.h"
#include "request_tracker_impl.h"
#include "visibility.h"

#include <thread>

namespace ravl
{
  RAVL_VISIBILITY std::shared_ptr<Claims> verify_synchronized(
    std::shared_ptr<const Attestation> attestation,
    const Options& options,
    std::shared_ptr<HTTPClient> http_client)
  {
    if (!http_client)
      http_client = std::make_shared<SynchronousHTTPClient>();

    auto request_tracker = std::make_shared<AttestationRequestTracker>();

    auto id = request_tracker->submit(
      options,
      attestation,
      http_client,
      [request_tracker](AttestationRequestTracker::RequestID id) {
        request_tracker->advance(id);
      });

    auto state = request_tracker->state(id);
    while (state != AttestationRequestTracker::FINISHED &&
           state != AttestationRequestTracker::ERROR)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      state = request_tracker->state(id);
    }

    if (state == AttestationRequestTracker::ERROR)
      throw std::runtime_error("error");

    auto r = request_tracker->result(id);
    request_tracker->erase(id);
    return r;
  }

  RAVL_VISIBILITY std::shared_ptr<Claims> verify_synchronous(
    std::shared_ptr<const Attestation> attestation, const Options& options)
  {
    auto http_client = std::make_shared<SynchronousHTTPClient>();
    auto requests = attestation->prepare_endorsements(options);
    std::optional<HTTPResponses> http_responses = std::nullopt;
    if (requests)
      http_client->submit(
        std::move(*requests), [&http_responses](HTTPResponses&& r) {
          http_responses = std::move(r);
        });
    return attestation->verify(options, http_responses);
  }
}
