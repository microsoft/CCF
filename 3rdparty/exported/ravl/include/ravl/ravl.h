// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "attestation.h"
#include "options.h"
#include "request_tracker.h"

#include <map>
#include <memory>
#include <mutex>

namespace ravl
{
  /// Synchronized verification (awaited async).
  /// Note: this uses std::this_thread::sleep_for.
  std::shared_ptr<Claims> verify_synchronized(
    std::shared_ptr<const Attestation> attestation,
    const Options& options = Options(),
    std::shared_ptr<HTTPClient> http_client = nullptr);

  /// Entirely synchronous verification (including endorsement download).
  std::shared_ptr<Claims> verify_synchronous(
    std::shared_ptr<const Attestation> attestation,
    const Options& options = Options());
}
