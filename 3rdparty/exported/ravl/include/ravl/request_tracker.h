// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "attestation.h"
#include "options.h"

#include <map>
#include <memory>
#include <mutex>

namespace ravl
{
  /// Tracker for asynchronous attestation verification.
  class AttestationRequestTracker
  {
  public:
    /// Constructor
    AttestationRequestTracker();

    /// Destructor
    virtual ~AttestationRequestTracker();

    typedef size_t RequestID;

    /// States of async verification requests.
    enum RequestState
    {
      SUBMITTED = 0,
      WAITING_FOR_ENDORSEMENTS,
      HAVE_ENDORSEMENTS,
      FINISHED,
      ERROR
    };

    /// Submit an async attestation verification request.
    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::shared_ptr<HTTPClient> http_client = nullptr,
      std::function<void(RequestID)>&& callback = nullptr);

    /// The state of an async verification request.
    RequestState state(RequestID id) const;

    /// Advance the state of an async verification request.
    RequestID advance(RequestID id);

    /// Predicate indicating completion of an async verification request.
    bool finished(RequestID id) const;

    /// Get the result of an async verification request.
    std::shared_ptr<Claims> result(RequestID id) const;

    /// Erase an async verification request (including its result).
    void erase(RequestID id);

  private:
    void* implementation;
  };
}
