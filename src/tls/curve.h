// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/stacktrace_utils.h"
#include "tls.h"
#include "hash.h"

#include <openssl/evp.h>
#include <mbedtls/ecp.h>
#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
#include <stdexcept>
#include <string>

namespace tls
{
  // SNIPPET_START: supported_curves
  enum class CurveID
  {
    NONE = 0,
    SECP384R1,
    SECP256K1,
    SECP256R1
  };

  static constexpr CurveID service_identity_curve_choice = CurveID::SECP384R1;
  // SNIPPET_END: supported_curves

  // 3 implementations of secp256k1 are available - mbedtls and bitcoin. Either
  // can be asked for explicitly via the CurveImpl enum. For cases where we
  // receive a raw 256k1 key/signature/cert only, this flag determines which
  // implementation is used
  static constexpr bool prefer_bitcoin_secp256k1 = true;

  // Helper to access elliptic curve id from context
  inline mbedtls_ecp_group_id get_mbedtls_ec_from_context(const mbedtls_pk_context& ctx)
  {
    return mbedtls_pk_ec(ctx)->grp.id;
  }

  // Get message digest algorithm to use for given elliptic curve
  inline MDType get_md_for_ec(CurveID ec, bool allow_none = false)
  {
    switch (ec)
    {
      case CurveID::SECP384R1: return MDType::SHA384;
      case CurveID::SECP256K1: return MDType::SHA256;
      case CurveID::SECP256R1: return MDType::SHA256;
      default:
      {
        if (allow_none)
        {
          return MDType::NONE;
        }
        else
        {
          stacktrace::print_stacktrace();
          const auto error = fmt::format("Unhandled CurveID: {}", ec);
          throw std::logic_error(error);
        }
      }
    }
  }

  inline mbedtls_md_type_t get_mbedtls_md_for_ec(mbedtls_ecp_group_id ec, bool allow_none = false)
  {
    switch (ec)
    {
      case MBEDTLS_ECP_DP_SECP384R1: return MBEDTLS_MD_SHA384;
      case MBEDTLS_ECP_DP_SECP256K1: return MBEDTLS_MD_SHA256;
      case MBEDTLS_ECP_DP_SECP256R1: return MBEDTLS_MD_SHA256;
      default:
      {
        if (allow_none)
        {
          return MBEDTLS_MD_NONE;
        }
        else
        {
          stacktrace::print_stacktrace();
          const auto error = fmt::format("Unhandled ecp group id: {}", ec);
          throw std::logic_error(error);
        }
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