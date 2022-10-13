// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "request_tracker.h"
#include "visibility.h"

#include <atomic>
#include <mutex>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{

  /// Internals of the asynchronous verification request tracker.
  class AttestationRequestTrackerImpl
  {
  public:
    using RequestID = AttestationRequestTracker::RequestID;
    using RequestState = AttestationRequestTracker::RequestState;

    struct Request
    {
      Request(
        AttestationRequestTracker::RequestState state,
        Options options,
        std::shared_ptr<const Attestation> attestation,
        std::shared_ptr<HTTPClient> http_client,
        std::function<void(RequestID)>&& callback) :
        state(state),
        options(options),
        attestation(attestation),
        http_client(http_client),
        callback(callback),
        http_request_set_id(std::nullopt)
      {}

      Request(const Request& other) = delete;
      AttestationRequestTracker::RequestState state = RequestState::ERROR;
      Options options;
      std::shared_ptr<const Attestation> attestation;
      std::shared_ptr<Claims> claims;
      std::shared_ptr<HTTPClient> http_client;
      std::function<void(RequestID)> callback;
      std::optional<HTTPRequestSetId> http_request_set_id;
    };

    using Requests = std::map<AttestationRequestTracker::RequestID, Request>;
    using HTTPResponseMap =
      std::map<AttestationRequestTracker::RequestID, HTTPResponses>;

    mutable std::mutex requests_mtx;
    Requests requests;
    std::shared_ptr<HTTPClient> http_client;
    std::atomic<AttestationRequestTracker::RequestID> next_request_id = 0;
    mutable std::mutex responses_mtx;
    HTTPResponseMap http_responses;

    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::shared_ptr<HTTPClient> http_client,
      std::function<void(RequestID)>&& callback)
    {
      RequestID request_id;
      Requests::iterator rit;

      {
        std::lock_guard<std::mutex> guard(responses_mtx);

        request_id = next_request_id++;

        auto [it, ok] = requests.try_emplace(
          request_id,
          RequestState::SUBMITTED,
          options,
          attestation,
          http_client,
          std::move(callback));

        if (!ok)
          throw std::bad_alloc();

        rit = it;
      }

      advance(request_id, rit->second);

      return request_id;
    }

    RequestState state(RequestID id) const
    {
      std::lock_guard<std::mutex> guard(requests_mtx);

      auto rit = requests.find(id);
      if (rit == requests.end())
        return RequestState::ERROR;
      else
        return rit->second.state;
    }

    RequestID advance(RequestID id, Request& req)
    {
      switch (req.state)
      {
        case RequestState::ERROR:
          throw std::runtime_error("verification request failed");
        case RequestState::SUBMITTED:
          req.state = RequestState::WAITING_FOR_ENDORSEMENTS;
          if (!prepare_endorsements(id, req))
          {
            req.state = RequestState::HAVE_ENDORSEMENTS;
            advance(id, req);
          }
          break;
        case RequestState::WAITING_FOR_ENDORSEMENTS:
          req.state = RequestState::HAVE_ENDORSEMENTS;
          break;
        case RequestState::HAVE_ENDORSEMENTS:
          verify(id, req);
          req.state = RequestState::FINISHED;
          if (req.callback)
            req.callback(id);
          break;
        case RequestState::FINISHED:
          break;
        default:
          throw std::runtime_error("unexpected request state");
      }

      return req.state;
    }

    bool finished(RequestID id) const
    {
      return state(id) == RequestState::FINISHED;
    }

    std::shared_ptr<Claims> result(RequestID id) const
    {
      std::lock_guard<std::mutex> guard(requests_mtx);

      auto rit = requests.find(id);
      if (rit == requests.end())
        throw std::runtime_error("no such attestation verification request");
      if (rit->second.state != RequestState::FINISHED)
        throw std::runtime_error(
          "attestation verification request not finished");
      if (!rit->second.claims)
        throw std::runtime_error("claim extraction failed");
      return rit->second.claims;
    }

    RAVL_VISIBILITY void erase(RequestID id)
    {
      std::lock_guard<std::mutex> guard(requests_mtx);

      auto rit = requests.find(id);
      if (rit != requests.end())
      {
        if (http_client && rit->second.http_request_set_id)
          http_client->erase(*rit->second.http_request_set_id);
        requests.erase(rit);
      }
    }

    AttestationRequestTracker::RequestID advance(RequestID id)
    {
      Requests::iterator rit;

      {
        std::lock_guard<std::mutex> guard(requests_mtx);
        rit = requests.find(id);
        if (rit == requests.end())
          throw std::runtime_error("request not found");
      }

      return advance(id, rit->second);
    }

    bool prepare_endorsements(RequestID id, Request& request)
    {
      if (!request.attestation)
        throw std::runtime_error("no attestation to verify");

      const auto& attestation = *request.attestation;
      const auto& options = request.options;
      auto http_client = request.http_client;

      if (options.verbosity > 0)
      {
        log(fmt::format(
          "* Verifying attestation from {}", to_string(attestation.source)));

        log("- Options", 2);
        if (options.fresh_endorsements)
          log("- Fresh endorsements", 4);
        if (options.fresh_root_ca_certificate)
          log("- Fresh root CA certificate", 4);
        if (options.root_ca_certificate)
          log("- Custom root CA certificate", 4);
        if (
          options.certificate_verification.ignore_time ||
          options.certificate_verification.verification_time)
        {
          log("- Certificate verification", 4);
          if (options.certificate_verification.ignore_time)
            log("- Ignore certificate times", 6);
          if (options.certificate_verification.verification_time)
            log("- Use custom certificate verification time", 6);
        }
      }

      std::optional<HTTPRequests> http_requests;
      try
      {
        http_requests = request.attestation->prepare_endorsements(options);
      }
      catch (const std::exception& ex)
      {
        if (options.verbosity > 0)
          log(fmt::format("  - endorsement preparation failed: {}", ex.what()));
        throw;
      }

      if (http_requests)
      {
        auto callback = [this, id](HTTPResponses&& r) {
          {
            std::lock_guard<std::mutex> guard(responses_mtx);
            auto [it, ok] = http_responses.emplace(id, r);
            if (!ok)
              throw std::bad_alloc();
          }
          advance(id);
          advance(id);
        };
        request.http_request_set_id =
          http_client->submit(std::move(*http_requests), callback);
        return true;
      }

      return false;
    }

    void verify(RequestID id, Request& request)
    {
      if (!request.attestation)
        throw std::runtime_error("no attestation to verify");

      auto& attestation = *request.attestation;
      const auto& options = request.options;
      auto http_client = request.http_client;

      std::shared_ptr<Claims> claims;

      try
      {
        std::lock_guard<std::mutex> guard(responses_mtx);
        std::vector<HTTPResponse> responses;

        auto rit = http_responses.find(id);
        if (rit != http_responses.end())
        {
          responses.swap(rit->second);
          http_responses.erase(rit);
        }

        claims = attestation.verify(options, responses);
      }
      catch (const std::exception& ex)
      {
        throw std::runtime_error(
          fmt::format("attestation verification failed: {}", ex.what()));
      }

      if (options.verbosity > 0)
        log("  - verification successful");

      request.claims = claims;
    }
  };

  RAVL_VISIBILITY AttestationRequestTracker::AttestationRequestTracker()
  {
    implementation = new AttestationRequestTrackerImpl();
  }

  RAVL_VISIBILITY AttestationRequestTracker::~AttestationRequestTracker()
  {
    delete static_cast<AttestationRequestTrackerImpl*>(implementation);
  }

  RAVL_VISIBILITY AttestationRequestTracker::RequestID
  AttestationRequestTracker::submit(
    const Options& options,
    std::shared_ptr<const Attestation> attestation,
    std::shared_ptr<HTTPClient> http_client,
    std::function<void(RequestID)>&& callback)
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->submit(options, attestation, http_client, std::move(callback));
  }

  RAVL_VISIBILITY AttestationRequestTracker::RequestState
  AttestationRequestTracker::state(RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->state(id);
  }

  RAVL_VISIBILITY bool AttestationRequestTracker::finished(RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->finished(id);
  }

  RAVL_VISIBILITY std::shared_ptr<Claims> AttestationRequestTracker::result(
    RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->result(id);
  }

  RAVL_VISIBILITY void AttestationRequestTracker::erase(RequestID id)
  {
    static_cast<AttestationRequestTrackerImpl*>(implementation)->erase(id);
  }

  RAVL_VISIBILITY AttestationRequestTracker::RequestID
  AttestationRequestTracker::advance(RequestID id)
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->advance(id);
  }
}