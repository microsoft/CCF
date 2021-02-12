// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/logger.h"
#include "tls.h"

#include <mbedtls/ecp.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>

using namespace crypto;

namespace tls
{
  // SNIPPET_START: supported_curves
  enum class CurveID
  {
    NONE = 0,
    SECP384R1,
    SECP256R1
  };

  static constexpr CurveID service_identity_curve_choice = CurveID::SECP384R1;
  // SNIPPET_END: supported_curves

  // Helper to access elliptic curve id from context
  inline mbedtls_ecp_group_id get_mbedtls_ec_from_context(
    const mbedtls_pk_context& ctx)
  {
    return mbedtls_pk_ec(ctx)->grp.id;
  }

  // Get message digest algorithm to use for given elliptic curve
  inline MDType get_md_for_ec(CurveID ec, bool allow_none = false)
  {
    switch (ec)
    {
      case CurveID::SECP384R1:
        return MDType::SHA384;
      case CurveID::SECP256R1:
        return MDType::SHA256;
      default:
      {
        if (allow_none)
        {
          return MDType::NONE;
        }
        else
        {
          throw std::logic_error(fmt::format("Unhandled CurveID: {}", ec));
        }
      }
    }
  }

  inline mbedtls_md_type_t get_mbedtls_md_for_ec(
    mbedtls_ecp_group_id ec, bool allow_none = false)
  {
    switch (ec)
    {
      case MBEDTLS_ECP_DP_SECP384R1:
        return MBEDTLS_MD_SHA384;
      case MBEDTLS_ECP_DP_SECP256R1:
        return MBEDTLS_MD_SHA256;
      default:
      {
        if (allow_none)
        {
          return MBEDTLS_MD_NONE;
        }
        else
        {
          const auto error = fmt::format("Unhandled ecp group id: {}", ec);
          throw std::logic_error(error);
        }
      }
    }
  }
}