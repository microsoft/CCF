// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_verifier.h"

#include "ccf/crypto/public_key.h"
#include "ccf/ds/logger.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "x509_time.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <t_cose/t_cose_sign1_verify.h>

namespace
{
  static std::string qcbor_buf_to_string(const UsefulBufC& buf)
  {
    return std::string(reinterpret_cast<const char*>(buf.ptr), buf.len);
  }

  static std::optional<int> extract_algorithm_from_header(
    std::span<const uint8_t> cose_msg)
  {
    UsefulBufC msg{cose_msg.data(), cose_msg.size()};
    QCBORError qcbor_result;

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

    struct q_useful_buf_c protected_parameters;
    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    QCBORDecode_EnterMap(&ctx, NULL);

    enum
    {
      ALG_INDEX,
      END_INDEX
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[ALG_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_ALG;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);
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
}

namespace ccf::crypto
{
  using namespace OpenSSL;

  COSECertVerifier_OpenSSL::COSECertVerifier_OpenSSL(
    const std::vector<uint8_t>& certificate)
  {
    Unique_BIO certbio(certificate);
    OpenSSL::Unique_X509 cert;
    if (!(cert = Unique_X509(certbio, true)))
    {
      BIO_reset(certbio);
      if (!(cert = Unique_X509(certbio, false)))
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", OpenSSL::error_string(ERR_get_error())));
      }
    }

    int mdnid, pknid, secbits;
    X509_get_signature_info(cert, &mdnid, &pknid, &secbits, 0);

    EVP_PKEY* pk = X509_get_pubkey(cert);

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    if (EVP_PKEY_get_base_id(pk) == EVP_PKEY_EC)
#else
    if (EVP_PKEY_get0_EC_KEY(pk))
#endif
    {
      public_key = std::make_shared<PublicKey_OpenSSL>(pk);
    }
    else
    {
      throw std::logic_error("unsupported public key type");
    }
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(const Pem& public_key_)
  {
    public_key = std::make_shared<PublicKey_OpenSSL>(public_key_);
  }

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() = default;

  bool COSEVerifier_OpenSSL::verify(
    const std::span<const uint8_t>& buf,
    std::span<uint8_t>& authned_content) const
  {
    EVP_PKEY* evp_key = *public_key;

    t_cose_key cose_key;
    cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    cose_key.k.key_ptr = evp_key;

    t_cose_sign1_verify_ctx verify_ctx;
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

    q_useful_buf_c buf_;
    buf_.ptr = buf.data();
    buf_.len = buf.size();

    q_useful_buf_c authned_content_;

    t_cose_err_t error =
      t_cose_sign1_verify(&verify_ctx, buf_, &authned_content_, nullptr);
    if (error == T_COSE_SUCCESS)
    {
      authned_content = {(uint8_t*)authned_content_.ptr, authned_content_.len};
      return true;
    }
    LOG_DEBUG_FMT("COSE Sign1 verification failed with error {}", error);
    return false;
  }

  bool COSEVerifier_OpenSSL::verify_detached(
    std::span<const uint8_t> buf, std::span<const uint8_t> payload) const
  {
    EVP_PKEY* evp_key = *public_key;

    const auto alg_header = extract_algorithm_from_header(buf);
    const auto alg_key = ccf::crypto::key_to_cose_alg_id(*public_key);
    if (!alg_header || !alg_key || alg_key != alg_header)
    {
      LOG_DEBUG_FMT(
        "COSE Sign1 verification: incompatible key IDS ({} vs {})",
        alg_header,
        alg_key);
      return false;
    }

    t_cose_key cose_key;
    cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    cose_key.k.key_ptr = evp_key;

    t_cose_sign1_verify_ctx verify_ctx;
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

    q_useful_buf_c buf_;
    buf_.ptr = buf.data();
    buf_.len = buf.size();

    q_useful_buf_c payload_;
    payload_.ptr = payload.data();
    payload_.len = payload.size();

    t_cose_err_t error = t_cose_sign1_verify_detached(
      &verify_ctx, buf_, NULL_Q_USEFUL_BUF_C, payload_, nullptr);

    if (error == T_COSE_SUCCESS)
    {
      return true;
    }

    LOG_DEBUG_FMT("COSE Sign1 verification failed with error {}", error);
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

  std::pair<std::string, std::string> extract_cose_endorsement_validity(
    std::span<const uint8_t> cose_msg)
  {
    UsefulBufC msg{cose_msg.data(), cose_msg.size()};
    QCBORError qcbor_result;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to parse COSE_Sign1 outer array");
      return {};
    }

    const uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      LOG_DEBUG_FMT("Failed to parse COSE_Sign1 tag");
      return {};
    }

    struct q_useful_buf_c protected_parameters;

    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to parse COSE_Sign1 as bstr");
      return {};
    }

    QCBORDecode_EnterMap(&ctx, NULL);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to parse COSE_Sign1 wrapped map");
      return {};
    }

    enum
    {
      FROM_INDEX,
      TILL_INDEX,
      END_INDEX
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[FROM_INDEX].label.string = UsefulBufC{
      ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN.data(),
      ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN.size()};
    header_items[FROM_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[FROM_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[TILL_INDEX].label.string = UsefulBufC{
      ccf::crypto::COSE_PHEADER_KEY_RANGE_END.data(),
      ccf::crypto::COSE_PHEADER_KEY_RANGE_END.size()};
    header_items[TILL_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[TILL_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to decode protected header");
      return {};
    }

    if (header_items[FROM_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      LOG_DEBUG_FMT("Failed to retrieve (missing) 'from' parameter");
      return {};
    }

    if (header_items[TILL_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      LOG_DEBUG_FMT("Failed to retrieve (missing) 'till' parameter");
      return {};
    }

    const auto from = qcbor_buf_to_string(header_items[FROM_INDEX].val.string);
    const auto till = qcbor_buf_to_string(header_items[TILL_INDEX].val.string);

    // Complete decode to ensure well-formed CBOR.

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to decode protected header: {}", qcbor_result);
      return {};
    }

    return {from, till};
  }
}
