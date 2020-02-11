// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls.h"

#include <stdexcept>
#include <string>

namespace tls
{
  enum class CurveImpl
  {
    secp384r1 = 1,
#ifdef MOD_MBEDTLS
    ed25519 = 2,
#endif
    secp256k1_mbedtls = 3,
    secp256k1_bitcoin = 4,

#if SERVICE_IDENTITY_CURVE_CHOICE_SECP384R1
    service_identity_curve_choice = secp384r1,
#elif SERVICE_IDENTITY_CURVE_CHOICE_ED25519
    service_identity_curve_choice = ed25519,
#elif SERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_MBEDTLS
    service_identity_curve_choice = secp256k1_mbedtls,
#elif SERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_BITCOIN
    service_identity_curve_choice = secp256k1_bitcoin,
#else
#  pragma message( \
    "No service identity curve specified - defaulting to secp384r1")
    service_identity_curve_choice = secp384r1,
#endif
  };

  // 2 implementations of secp256k1 are available - mbedtls and bitcoin. Either
  // can be asked for explicitly via the CurveImpl enum. For cases where we
  // receive a raw 256k1 key/signature/cert only, this flag determines which
  // implementation is used
  static constexpr bool prefer_bitcoin_secp256k1 = true;

  // Helper to access elliptic curve id from context
  inline mbedtls_ecp_group_id get_ec_from_context(const mbedtls_pk_context& ctx)
  {
    return mbedtls_pk_ec(ctx)->grp.id;
  }

  // Get mbedtls elliptic curve for given CCF curve implementation
  inline mbedtls_ecp_group_id get_ec_for_curve_impl(CurveImpl curve)
  {
    switch (curve)
    {
      case CurveImpl::secp384r1:
      {
        return MBEDTLS_ECP_DP_SECP384R1;
      }
#ifdef MOD_MBEDTLS
      case CurveImpl::ed25519:
      {
        return MBEDTLS_ECP_DP_CURVE25519;
      }
#endif
      case CurveImpl::secp256k1_mbedtls:
      case CurveImpl::secp256k1_bitcoin:
      {
        return MBEDTLS_ECP_DP_SECP256K1;
      }
      default:
      {
        throw std::logic_error(
          "Unhandled curve type: " +
          std::to_string(static_cast<size_t>(curve)));
      }
    }
  }

  // Get message digest algorithm to use for given elliptic curve
  inline mbedtls_md_type_t get_md_for_ec(mbedtls_ecp_group_id ec)
  {
    switch (ec)
    {
      case MBEDTLS_ECP_DP_SECP384R1:
      {
        return MBEDTLS_MD_SHA384;
      }
#ifdef MOD_MBEDTLS
      case MBEDTLS_ECP_DP_CURVE25519:
      {
        return MBEDTLS_MD_SHA512;
      }
#endif
      case MBEDTLS_ECP_DP_SECP256K1:
      {
        return MBEDTLS_MD_SHA256;
      }
      default:
      {
        throw std::logic_error(
          std::string("Unhandled ecp group id: ") +
          mbedtls_ecp_curve_info_from_grp_id(ec)->name);
      }
    }
  }

}