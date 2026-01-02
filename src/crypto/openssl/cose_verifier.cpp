// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_verifier.h"

#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "ds/internal_logger.h"
#include "x509_time.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <t_cose/t_cose_sign1_verify.h>

namespace
{
  std::string qcbor_buf_to_string(const UsefulBufC& buf)
  {
    return {reinterpret_cast<const char*>(buf.ptr), buf.len};
  }

  std::optional<int> extract_algorithm_from_header(
    std::span<const uint8_t> cose_msg)
  {
    UsefulBufC msg{cose_msg.data(), cose_msg.size()};
    QCBORError qcbor_result = QCBOR_SUCCESS;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to parse COSE_Sign1 outer array");
      return std::nullopt;
    }

    const uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      LOG_DEBUG_FMT("Failed to parse COSE_Sign1 tag");
      return std::nullopt;
    }

    q_useful_buf_c protected_parameters = {};
    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    QCBORDecode_EnterMap(&ctx, nullptr);

    enum HeaderIndex : uint8_t
    {
      ALG_INDEX,
      END_INDEX
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[ALG_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_ALG;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, static_cast<QCBORItem*>(header_items));
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to decode protected header");
      return std::nullopt;
    }

    if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      LOG_DEBUG_FMT("Failed to retrieve (missing) 'alg' parameter");
      return std::nullopt;
    }

    const int alg = header_items[ALG_INDEX].val.int64;

    // Complete decode to ensure well-formed CBOR.

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to decode protected header: {}", qcbor_result);
      return std::nullopt;
    }

    return alg;
  }

  q_useful_buf_c buf_from_span(const std::span<const uint8_t> span)
  {
    return {.ptr = span.data(), .len = span.size()};
  }

  class TCOSEVerify
  {
  private:
    EVP_PKEY* pkey = nullptr;
    t_cose_key cose_key = {};

  public:
    t_cose_sign1_verify_ctx ctx = {};

    TCOSEVerify(
      std::shared_ptr<ccf::crypto::PublicKey_OpenSSL> pkey_,
      const std::span<const uint8_t> envelope) :
      pkey(*pkey_)
    {
      const auto alg_header = extract_algorithm_from_header(envelope);
      if (!alg_header.has_value())
      {
        throw std::domain_error("COSE header is missing 'alg' parameter");
      }

      pkey_->check_is_cose_compatible(alg_header.value());

      cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
      cose_key.k.key_ptr = pkey;

      t_cose_sign1_verify_init(&ctx, T_COSE_OPT_TAG_REQUIRED);
      t_cose_sign1_set_verification_key(&ctx, cose_key);
    }
  };

}

namespace ccf::crypto
{
  using namespace OpenSSL;

  COSECertVerifier_OpenSSL::COSECertVerifier_OpenSSL(
    const std::vector<uint8_t>& certificate)
  {
    Unique_BIO certbio(certificate);
    OpenSSL::Unique_X509 cert;
    if ((cert = Unique_X509(certbio, true)) == nullptr)
    {
      BIO_reset(certbio);
      if ((cert = Unique_X509(certbio, false)) == nullptr)
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", OpenSSL::error_string(ERR_get_error())));
      }
    }
    EVP_PKEY* pk = X509_get_pubkey(cert);

    public_key = std::make_shared<PublicKey_OpenSSL>(pk);
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(const Pem& public_key_)
  {
    public_key = std::make_shared<PublicKey_OpenSSL>(public_key_);
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(
    std::span<const uint8_t> public_key_der_)
  {
    public_key = std::make_shared<PublicKey_OpenSSL>(public_key_der_);
  }

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() = default;

  bool COSEVerifier_OpenSSL::verify(
    const std::span<const uint8_t>& envelope,
    std::span<uint8_t>& authned_content) const
  {
    try
    {
      TCOSEVerify cose_verify(public_key, envelope);
      q_useful_buf_c envelope_ = buf_from_span(envelope);

      q_useful_buf_c authned_content_ = {};

      t_cose_err_t error = t_cose_sign1_verify(
        &cose_verify.ctx, envelope_, &authned_content_, nullptr);
      if (error == T_COSE_SUCCESS)
      {
        authned_content = {
          reinterpret_cast<uint8_t*>(const_cast<void*>(authned_content_.ptr)),
          authned_content_.len};
        return true;
      }

      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", error);
    }
    catch (const std::exception& e)
    {
      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", e.what());
    }
    return false;
  }

  bool COSEVerifier_OpenSSL::verify_detached(
    std::span<const uint8_t> envelope, std::span<const uint8_t> payload) const
  {
    try
    {
      TCOSEVerify cose_verify(public_key, envelope);

      q_useful_buf_c envelope_ = buf_from_span(envelope);

      q_useful_buf_c payload_ = {};
      payload_.ptr = payload.data();
      payload_.len = payload.size();

      t_cose_err_t error = t_cose_sign1_verify_detached(
        &cose_verify.ctx, envelope_, NULL_Q_USEFUL_BUF_C, payload_, nullptr);

      if (error == T_COSE_SUCCESS)
      {
        return true;
      }

      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", error);
    }
    catch (const std::exception& e)
    {
      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", e.what());
    }
    return false;
  }

  COSEVerifierUniquePtr make_cose_verifier_from_cert(
    const std::vector<uint8_t>& cert)
  {
    return std::make_unique<COSECertVerifier_OpenSSL>(cert);
  }

  COSEVerifierUniquePtr make_cose_verifier_from_key(const Pem& public_key)
  {
    return std::make_unique<COSEKeyVerifier_OpenSSL>(public_key);
  }

  COSEVerifierUniquePtr make_cose_verifier_from_key(
    std::span<const uint8_t> public_key)
  {
    return std::make_unique<COSEKeyVerifier_OpenSSL>(public_key);
  }

  COSEEndorsementValidity extract_cose_endorsement_validity(
    std::span<const uint8_t> cose_msg)
  {
    UsefulBufC msg{cose_msg.data(), cose_msg.size()};
    QCBORError qcbor_result = QCBOR_SUCCESS;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 outer array");
    }

    const uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 tag");
    }

    q_useful_buf_c protected_parameters = {};

    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 as bstr");
    }

    QCBORDecode_EnterMap(&ctx, nullptr); // phdr
    QCBORDecode_EnterMapFromMapSZ(&ctx, "ccf.v1"); // phdr["ccf.v1"]

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 wrapped map");
    }

    enum HeaderIndex : uint8_t
    {
      FROM_INDEX,
      TO_INDEX,
      END_INDEX
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[FROM_INDEX].label.string = UsefulBufC{
      ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN.data(),
      ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN.size()};
    header_items[FROM_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[FROM_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[TO_INDEX].label.string = UsefulBufC{
      ccf::crypto::COSE_PHEADER_KEY_RANGE_END.data(),
      ccf::crypto::COSE_PHEADER_KEY_RANGE_END.size()};
    header_items[TO_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[TO_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, static_cast<QCBORItem*>(header_items));
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to decode protected header");
    }

    if (header_items[FROM_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw std::logic_error(fmt::format(
        "Failed to retrieve (missing) {} parameter",
        ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN));
    }

    if (header_items[TO_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw std::logic_error(fmt::format(
        "Failed to retrieve (missing) {} parameter",
        ccf::crypto::COSE_PHEADER_KEY_RANGE_END));
    }

    const auto from = qcbor_buf_to_string(header_items[FROM_INDEX].val.string);
    const auto to = qcbor_buf_to_string(header_items[TO_INDEX].val.string);

    // Complete decode to ensure well-formed CBOR.

    QCBORDecode_ExitMap(&ctx); // phdr["ccf.v1"]
    QCBORDecode_ExitMap(&ctx); // phdr
    QCBORDecode_ExitBstrWrapped(&ctx);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error(fmt::format(
        "Failed to decode protected header with error code: {}", qcbor_result));
    }

    return COSEEndorsementValidity{.from_txid = from, .to_txid = to};
  }
}
