// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/key_pair.h"

#include <openssl/ossl_typ.h>
#include <span>
#include <string>
#include <t_cose/t_cose_sign1_sign.h>
#include <unordered_map>

namespace ccf::crypto
{
  // Algorithm used to sign, standardatised field
  static constexpr int64_t COSE_PHEADER_KEY_ALG = 1;
  // Verifiable data structure, standartised field
  static constexpr int64_t COSE_PHEADER_KEY_VDS = 395;
  // CCF-specifix, last signed TxID
  static constexpr const char* COSE_PHEADER_KEY_TXID = "ccf.txid";

  class COSEParametersFactory
  {
  public:
    template <typename Callable>
    COSEParametersFactory(Callable&& impl, size_t args_size) :
      impl(std::forward<Callable>(impl)),
      args_size{args_size}
    {}

    void apply(QCBOREncodeContext* ctx) const
    {
      impl(ctx);
    }

    size_t estimated_size() const
    {
      return args_size;
    }

  private:
    std::function<void(QCBOREncodeContext*)> impl{};
    size_t args_size{};
  };

  COSEParametersFactory cose_params_int_int(int64_t key, int64_t value);

  COSEParametersFactory cose_params_int_string(
    int64_t key, std::string_view value);

  COSEParametersFactory cose_params_string_int(
    std::string_view key, int64_t value);

  COSEParametersFactory cose_params_string_string(
    std::string_view key, std::string_view value);

  struct COSESignError : public std::runtime_error
  {
    COSESignError(const std::string& msg) : std::runtime_error(msg) {}
  };

  /* Sign a cose_sign1 payload with custom protected headers as strings, where
       - key: integer label to be assigned in a COSE value
       - value: string behind the label.

    Labels have to be unique. For standardised labels list check
    https://www.iana.org/assignments/cose/cose.xhtml#header-parameters.
   */
  std::vector<uint8_t> cose_sign1(
    KeyPair_OpenSSL& key,
    const std::vector<COSEParametersFactory>& protected_headers,
    std::span<const uint8_t> payload);
}
