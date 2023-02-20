// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <qcbor/qcbor.h>
#include <stdexcept>
#include <string>
#include <t_cose/t_cose_common.h>

namespace ccf::cose
{
  namespace headers
  {
    static constexpr int64_t PARAM_ALG = 1;
    static constexpr int64_t PARAM_CONTENT_TYPE = 3;
    static constexpr int64_t PARAM_KID = 4;
    static constexpr int64_t PARAM_X5CHAIN = 33;

    static constexpr auto CONTENT_TYPE_APPLICATION_JSON_VALUE =
      "application/json";
  }

  using Signature = std::span<const uint8_t>;

  static std::string qcbor_buf_to_string(const UsefulBufC& buf)
  {
    return std::string(reinterpret_cast<const char*>(buf.ptr), buf.len);
  }

  static std::vector<uint8_t> qcbor_buf_to_byte_vector(const UsefulBufC& buf)
  {
    auto ptr = static_cast<const uint8_t*>(buf.ptr);
    return {ptr, ptr + buf.len};
  }

  static bool is_ecdsa_alg(int64_t cose_alg)
  {
    return cose_alg == T_COSE_ALGORITHM_ES256 ||
      cose_alg == T_COSE_ALGORITHM_ES384 || cose_alg == T_COSE_ALGORITHM_ES512;
  }

  static bool is_rsa_alg(int64_t cose_alg)
  {
    return cose_alg == T_COSE_ALGORITHM_PS256 ||
      cose_alg == T_COSE_ALGORITHM_PS384 || cose_alg == T_COSE_ALGORITHM_PS512;
  }

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  struct COSESignatureValidationError : public std::runtime_error
  {
    COSESignatureValidationError(const std::string& msg) :
      std::runtime_error(msg)
    {}
  };

}