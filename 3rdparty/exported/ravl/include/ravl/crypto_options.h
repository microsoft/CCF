// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <ctime>
#include <optional>

namespace ravl
{
  namespace crypto
  {
    struct CertificateValidationOptions
    {
      /// Ignores certificate validity dates
      bool ignore_time = false;

      /// Sets an explicit verification time (as opposed to current time)
      std::optional<time_t> verification_time = std::nullopt;
    };
  }
}
