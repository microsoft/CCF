// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>
#include <stdexcept>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "ccf/crypto/mldsa_parameter_set.h"
#  include "ccf/crypto/openssl/openssl_wrappers.h"

#  include <openssl/core_names.h>
#  include <openssl/obj_mac.h>
#  include <openssl/params.h>
#  include <optional>
#  include <span>
#  include <string_view>

namespace ccf::crypto::mldsa
{
  inline const char* openssl_name(MLDSAParameterSet parameter_set)
  {
    switch (parameter_set)
    {
      case MLDSAParameterSet::ML_DSA_44:
      {
        return LN_ML_DSA_44;
      }
      case MLDSAParameterSet::ML_DSA_65:
      {
        return LN_ML_DSA_65;
      }
      case MLDSAParameterSet::ML_DSA_87:
      {
        return LN_ML_DSA_87;
      }
      default:
      {
        throw std::invalid_argument("Unknown ML-DSA parameter set");
      }
    }
  }

  /// The key's parameter set, or nullopt when it is not an ML-DSA key.
  inline std::optional<MLDSAParameterSet> find_parameter_set(
    const EVP_PKEY* key)
  {
    const auto* type_name = EVP_PKEY_get0_type_name(key);
    if (type_name == nullptr)
    {
      throw std::runtime_error(fmt::format(
        "OpenSSL error loading key type name: {}", OpenSSL::first_error()));
    }

    const std::string_view name(type_name);
    if (name == LN_ML_DSA_44)
    {
      return MLDSAParameterSet::ML_DSA_44;
    }
    if (name == LN_ML_DSA_65)
    {
      return MLDSAParameterSet::ML_DSA_65;
    }
    if (name == LN_ML_DSA_87)
    {
      return MLDSAParameterSet::ML_DSA_87;
    }
    return std::nullopt;
  }

  /// Returns the key's parameter set; with an expected set, a mismatch throws.
  inline MLDSAParameterSet parameter_set(
    EVP_PKEY* key, std::optional<MLDSAParameterSet> expected = std::nullopt)
  {
    if (key == nullptr)
    {
      throw std::logic_error("ML-DSA key is not initialized");
    }

    const auto found = find_parameter_set(key);
    if (!found.has_value())
    {
      throw std::invalid_argument("Expected an ML-DSA key");
    }
    if (expected.has_value() && found.value() != expected.value())
    {
      throw std::invalid_argument(
        "ML-DSA key uses an unexpected parameter set");
    }
    return found.value();
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
#else // Remove this fallback after dropping AL3 support.

namespace ccf::crypto::mldsa
{
  /// Body of every ML-DSA factory on builds without ML-DSA support.
  [[noreturn]] inline void unsupported()
  {
    throw std::runtime_error("ML-DSA requires OpenSSL 3.5 or newer");
  }
}
#endif // OPENSSL_VERSION_PREREQ
