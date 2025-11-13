// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/ec_key_pair.h"

#include <openssl/ossl_typ.h>
#include <span>
#include <string>
#include <t_cose/t_cose_sign1_sign.h>
#include <unordered_map>

namespace ccf::crypto
{
  // Standardised field: algorithm used to sign.
  static constexpr int64_t COSE_PHEADER_KEY_ALG = 1;
  // Standardised: hash of the signing key.
  static constexpr int64_t COSE_PHEADER_KEY_ID = 4;
  // Standardised: CWT claims map.
  static constexpr int64_t COSE_PHEADER_KEY_CWT = 15;
  // Standardised: verifiable data structure.
  static constexpr int64_t COSE_PHEADER_KEY_VDS = 395;
  // Standardised: issued at CWT claim. Value is **PLAIN INTEGER**, as per
  // https://www.rfc-editor.org/rfc/rfc8392#section-2. Quote:
  /* The "NumericDate" term in this specification has the same meaning and
   * processing rules as the JWT "NumericDate" term defined in Section 2 of
   * [RFC7519], except that it is represented as a CBOR numericdate (from
   * Section 2.4.1 of [RFC7049]) instead of a JSON number.  The  encoding is
   * modified so that the leading tag 1 (epoch-based date/time) MUST  be
   * omitted.
   */
  static constexpr int64_t COSE_PHEADER_KEY_IAT = 6;
  // Standardised: issuer CWT claim.
  // https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
  /* The "iss" (issuer) claim identifies the principal that issued the CWT.
   * The "iss" value is a case-sensitive string containing a StringOrURI value.
   */
  static constexpr int64_t COSE_PHEADER_KEY_ISS = 1;
  // Standardised: subject CWT claim.
  // https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
  /* The "sub" (subject) claim identifies the principal that is the subject of
   * the CWT.  The claims in a CWT are normally statements about the subject.
   * The "sub" value is a case-sensitive string containing a StringOrURI value.
   */
  static constexpr int64_t COSE_PHEADER_KEY_SUB = 2;
  // CCF headers nested map key.
  static const std::string COSE_PHEADER_KEY_CCF = "ccf.v1";
  // CCF-specific: last signed TxID.
  static const std::string COSE_PHEADER_KEY_TXID = "txid";
  // CCF-specific: first TX in the range.
  static const std::string COSE_PHEADER_KEY_RANGE_BEGIN = "epoch.start.txid";
  // CCF-specific: last TX included in the range.
  static const std::string COSE_PHEADER_KEY_RANGE_END = "epoch.end.txid";
  // CCF-specific: last signed Merkle root hash in the range.
  static const std::string COSE_PHEADER_KEY_EPOCH_LAST_MERKLE_ROOT =
    "epoch.end.merkle.root";

  class COSEMapKey
  {
  public:
    virtual void apply(QCBOREncodeContext* ctx) const = 0;
    virtual size_t estimated_size() const = 0;

    virtual ~COSEMapKey() = default;
  };

  class COSEMapIntKey : public COSEMapKey
  {
  public:
    COSEMapIntKey(int64_t key_);
    ~COSEMapIntKey() override = default;

    void apply(QCBOREncodeContext* ctx) const override;
    size_t estimated_size() const override;

  private:
    int64_t key;
  };

  class COSEMapStringKey : public COSEMapKey
  {
  public:
    COSEMapStringKey(std::string key_);
    ~COSEMapStringKey() override = default;

    void apply(QCBOREncodeContext* ctx) const override;
    size_t estimated_size() const override;

  private:
    std::string key;
  };

  class COSEParametersFactory
  {
  public:
    virtual void apply(QCBOREncodeContext* ctx) const = 0;
    virtual size_t estimated_size() const = 0;

    virtual ~COSEParametersFactory() = default;
  };

  class COSEParametersMap : public COSEParametersFactory
  {
  public:
    COSEParametersMap(
      std::shared_ptr<COSEMapKey> key_,
      const std::vector<std::shared_ptr<COSEParametersFactory>>& factories_);

    void apply(QCBOREncodeContext* ctx) const override;
    size_t estimated_size() const override;

    virtual ~COSEParametersMap() = default;

  private:
    std::shared_ptr<COSEMapKey> key;
    std::vector<std::shared_ptr<COSEParametersFactory>> factories{};
  };

  std::shared_ptr<COSEParametersFactory> cose_params_int_int(
    int64_t key, int64_t value);

  std::shared_ptr<COSEParametersFactory> cose_params_int_string(
    int64_t key, const std::string& value);

  std::shared_ptr<COSEParametersFactory> cose_params_string_int(
    const std::string& key, int64_t value);

  std::shared_ptr<COSEParametersFactory> cose_params_string_string(
    const std::string& key, const std::string& value);

  std::shared_ptr<COSEParametersFactory> cose_params_int_bytes(
    int64_t key, std::span<const uint8_t> value);

  std::shared_ptr<COSEParametersFactory> cose_params_string_bytes(
    const std::string& key, std::span<const uint8_t> value);

  class COSEParametersPair : public COSEParametersFactory
  {
  public:
    template <typename Callable>
    COSEParametersPair(Callable&& impl, size_t args_size) :
      impl(std::forward<Callable>(impl)),
      args_size{args_size}
    {}

    virtual ~COSEParametersPair() = default;

    void apply(QCBOREncodeContext* ctx) const override
    {
      impl(ctx);
    }

    size_t estimated_size() const override
    {
      return args_size;
    }

  private:
    std::function<void(QCBOREncodeContext*)> impl{};
    size_t args_size{};
  };

  using COSEHeadersArray =
    std::vector<std::shared_ptr<ccf::crypto::COSEParametersFactory>>;

  struct COSESignError : public std::runtime_error
  {
    COSESignError(const std::string& msg) : std::runtime_error(msg) {}
  };

  std::optional<int> key_to_cose_alg_id(
    const ccf::crypto::ECPublicKey_OpenSSL& key);

  /* Sign a cose_sign1 payload with custom protected headers as strings, where
       - key: integer label to be assigned in a COSE value
       - value: string behind the label.

    Labels have to be unique. For standardised labels list check
    https://www.iana.org/assignments/cose/cose.xhtml#header-parameters.
   */
  std::vector<uint8_t> cose_sign1(
    const ECKeyPair_OpenSSL& key,
    const std::vector<std::shared_ptr<COSEParametersFactory>>&
      protected_headers,
    std::span<const uint8_t> payload,
    bool detached_payload = true);
}
