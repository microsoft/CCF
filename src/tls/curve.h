// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "tls.h"

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
#include <stdexcept>
#include <string>

namespace tls
{
  // SNIPPET_START: supported_curves
  enum class CurveImpl
  {
    secp384r1 = 1,
#ifdef MOD_MBEDTLS
    ed25519 = 2,
#endif
    secp256k1_mbedtls = 3,
    secp256k1_bitcoin = 4,

    service_identity_curve_choice = secp384r1,
  };
  // SNIPPET_END: supported_curves

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

  inline bool verify_secp256k_bc(
    secp256k1_context* ctx,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* hash,
    size_t hash_size,
    const secp256k1_pubkey* public_key)
  {
    if (hash_size != 32)
      return false;

    secp256k1_ecdsa_signature sig;
    if (
      secp256k1_ecdsa_signature_parse_der(
        ctx, &sig, signature, signature_size) != 1)
      return false;

    secp256k1_ecdsa_signature norm_sig;
    if (secp256k1_ecdsa_signature_normalize(ctx, &norm_sig, &sig) == 1)
    {
      LOG_TRACE_FMT("secp256k1 normalized a signature to lower-S form");
    }

    return secp256k1_ecdsa_verify(ctx, &norm_sig, hash, public_key) == 1;
  }

  static void secp256k1_illegal_callback(const char* str, void*)
  {
    throw std::logic_error(
      fmt::format("[libsecp256k1] illegal argument: {}", str));
  }

  // Wrap calls to secp256k1_context_create, setting illegal callback to throw
  // catchable errors rather than aborting, and ensuring destroy is called when
  // this goes out of scope
  class BCk1Context
  {
  public:
    secp256k1_context* p = nullptr;

    BCk1Context(unsigned int flags)
    {
      p = secp256k1_context_create(flags);

      secp256k1_context_set_illegal_callback(
        p, secp256k1_illegal_callback, nullptr);
    }

    ~BCk1Context()
    {
      secp256k1_context_destroy(p);
    }
  };

  using BCk1ContextPtr = std::unique_ptr<BCk1Context>;

  inline BCk1ContextPtr make_bc_context(unsigned int flags)
  {
    return std::make_unique<BCk1Context>(flags);
  }
}