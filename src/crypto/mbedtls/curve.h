// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/curve.h"

#include "crypto/hash.h"

#include <mbedtls/ecp.h>
#include <stdexcept>
#include <string>

namespace crypto
{
  // Helper to access elliptic curve id from context
  inline mbedtls_ecp_group_id get_mbedtls_ec_from_context(
    const mbedtls_pk_context& ctx)
  {
    return mbedtls_pk_ec(ctx)->grp.id;
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