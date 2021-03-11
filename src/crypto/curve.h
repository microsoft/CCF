// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/logger.h"

#include <mbedtls/ecp.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>

namespace crypto
{
  // SNIPPET_START: supported_curves
  enum class CurveID
  {
    /// No curve
    NONE = 0,
    /// The SECP384R1 curve
    SECP384R1,
    /// The SECP256R1 curve
    SECP256R1
  };

  static constexpr CurveID service_identity_curve_choice = CurveID::SECP384R1;
  // SNIPPET_END: supported_curves

  // Get message digest algorithm to use for given elliptic curve
  inline MDType get_md_for_ec(CurveID ec)
  {
    switch (ec)
    {
      case CurveID::SECP384R1:
        return MDType::SHA384;
      case CurveID::SECP256R1:
        return MDType::SHA256;
      default:
      {
        throw std::logic_error(fmt::format("Unhandled CurveID: {}", ec));
      }
    }
  }
}