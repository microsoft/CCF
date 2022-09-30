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
  /// Tracker for asynchronous attestation verification
  class AttestationRequestTracker
  {
  public:
    AttestationRequestTracker();

    virtual ~AttestationRequestTracker();

    typedef size_t RequestID;

    enum RequestState
    {
      SUBMITTED = 0,
      WAITING_FOR_ENDORSEMENTS,
      HAVE_ENDORSEMENTS,
      FINISHED,
      ERROR
    };

    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::shared_ptr<HTTPClient> http_client = nullptr,
      std::function<void(RequestID)>&& callback = nullptr);

    RequestState state(RequestID id) const;
    RequestID advance(RequestID id);
    bool finished(RequestID id) const;
    std::shared_ptr<Claims> result(RequestID id) const;
    void erase(RequestID id);

  private:
    void* implementation;
  };

  /// Synchronized verification (including endorsement download).
  std::shared_ptr<Claims> verify(
    std::shared_ptr<const Attestation> attestation,
    const Options& options = Options(),
    std::shared_ptr<HTTPClient> http_client = nullptr);

  /// Entirely synchronous verification (including endorsement download).
  std::shared_ptr<Claims> verify_sync(
    std::shared_ptr<const Attestation> attestation,
    const Options& options = Options());
}
