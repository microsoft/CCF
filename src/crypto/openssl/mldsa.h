// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "ccf/crypto/mldsa_parameter_set.h"
#  include "ccf/crypto/openssl/openssl_wrappers.h"

#  include <openssl/core_names.h>
#  include <openssl/obj_mac.h>
#  include <openssl/params.h>
#  include <optional>
#  include <span>
#  include <stdexcept>

namespace ccf::crypto::mldsa
{
  inline const char* openssl_name(MLDSAParameterSet parameter_set)
  {
    switch (parameter_set)
    {
      case MLDSAParameterSet::ML_DSA_44:
        return LN_ML_DSA_44;
      case MLDSAParameterSet::ML_DSA_65:
        return LN_ML_DSA_65;
      case MLDSAParameterSet::ML_DSA_87:
        return LN_ML_DSA_87;
      default:
        throw std::invalid_argument("Unknown ML-DSA parameter set");
    }
  }

  /// Returns the key's parameter set; with an expected set, a mismatch throws.
  inline MLDSAParameterSet parameter_set(
    EVP_PKEY* key, std::optional<MLDSAParameterSet> expected = std::nullopt)
  {
    if (key == nullptr)
    {
      throw std::logic_error("ML-DSA key is not initialized");
    }

    for (const auto candidate :
         {MLDSAParameterSet::ML_DSA_44,
          MLDSAParameterSet::ML_DSA_65,
          MLDSAParameterSet::ML_DSA_87})
    {
      if (EVP_PKEY_is_a(key, openssl_name(candidate)) == 1)
      {
        if (expected.has_value() && candidate != expected.value())
        {
          throw std::invalid_argument(
            "ML-DSA key uses an unexpected parameter set");
        }
        return candidate;
      }
    }
    throw std::invalid_argument("Expected an ML-DSA key");
  }

  /// Binds a caller-supplied context string to a signature operation.
  inline void set_context(EVP_PKEY_CTX* ctx, std::span<const uint8_t> context)
  {
    if (context.empty())
    {
      throw std::logic_error("ML-DSA context string is empty");
    }

    // Providers may ignore unrecognised parameters, so the context parameter
    // must be settable before the signature operation can rely on it.
    const auto* settable = EVP_PKEY_CTX_settable_params(ctx);
    const auto* param =
      OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (param == nullptr)
    {
      throw std::runtime_error(
        "ML-DSA provider does not support context strings");
    }
    if (param->data_type != OSSL_PARAM_OCTET_STRING)
    {
      throw std::runtime_error(
        "ML-DSA provider requires an incompatible context parameter type");
    }

    OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        const_cast<uint8_t*>(context.data()),
        context.size()),
      OSSL_PARAM_construct_end()};
    OpenSSL::CHECK1(EVP_PKEY_CTX_set_params(ctx, params));
  }
}
#endif // OPENSSL_VERSION_PREREQ
