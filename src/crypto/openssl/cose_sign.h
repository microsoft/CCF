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
  // Standardised field: algorithm used to sign
  static constexpr int64_t COSE_PHEADER_KEY_ALG = 1;
  // Standardised: hash of the signing key
  static constexpr int64_t COSE_PHEADER_KEY_ID = 4;
  // Standardised: verifiable data structure
  static constexpr int64_t COSE_PHEADER_KEY_VDS = 395;
  // CCF-specific: last signed TxID
  static const std::string COSE_PHEADER_KEY_TXID = "ccf.txid";
  // CCF-specific: first TX in the range.
  static const std::string COSE_PHEADER_KEY_RANGE_BEGIN = "ccf.range.begin";
  // CCF-specific: last TX included in the range.
  static const std::string COSE_PHEADER_KEY_RANGE_END = "ccf.epoch.end";

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
    int64_t key, const std::string& value);

  COSEParametersFactory cose_params_string_int(
    const std::string& key, int64_t value);

  COSEParametersFactory cose_params_string_string(
    const std::string& key, const std::string& value);

  COSEParametersFactory cose_params_int_bytes(
    int64_t key, const std::vector<uint8_t>& value);

  COSEParametersFactory cose_params_string_bytes(
    const std::string& key, const std::vector<uint8_t>& value);

  struct COSESignError : public std::runtime_error
  {
    COSESignError(const std::string& msg) : std::runtime_error(msg) {}
  };

  std::optional<int> key_to_cose_alg_id(
    const ccf::crypto::PublicKey_OpenSSL& key);

  /* Sign a cose_sign1 payload with custom protected headers as strings, where
       - key: integer label to be assigned in a COSE value
       - value: string behind the label.

    Labels have to be unique. For standardised labels list check
    https://www.iana.org/assignments/cose/cose.xhtml#header-parameters.
   */
  std::vector<uint8_t> cose_sign1(
    const KeyPair_OpenSSL& key,
    const std::vector<COSEParametersFactory>& protected_headers,
    std::span<const uint8_t> payload,
    bool detached_payload = true);
}
