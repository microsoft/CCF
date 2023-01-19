// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/base64.h"
#include "ccf/ds/json.h"
#include "crypto/openssl/cose_verifier.h"

#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <span>
#include <t_cose/t_cose_sign1_verify.h>

namespace ccf
{
  struct UVMEndorsementsPayload
  {
    std::string maa_api_version;
    std::string sevsnpvn_guest_svn;
    std::string sevsnpvm_launch_measurement;
  };
  DECLARE_JSON_TYPE(UVMEndorsementsPayload);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
    UVMEndorsementsPayload,
    maa_api_version,
    "x-ms-maa-api-version",
    sevsnpvn_guest_svn,
    "x-ms-sevsnpvm-guestsvn",
    sevsnpvm_launch_measurement,
    "x-ms-sevsnpvm-launchmeasurement");

  struct ProtectedHeader
  {
    int64_t alg;
    std::string content_type;
    std::vector<std::vector<uint8_t>> x5_chain;
    std::string iss;
    std::string feed;
  };

  static constexpr int64_t COSE_HEADER_PARAM_ALG = 1;
  static constexpr int64_t COSE_HEADER_PARAM_CONTENT_TYPE = 3;
  static constexpr int64_t COSE_HEADER_PARAM_X5CHAIN = 33;

  static std::string qcbor_buf_to_string(const UsefulBufC& buf)
  {
    return {static_cast<const char*>(buf.ptr), buf.len};
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

  static ProtectedHeader decode_protected_header(
    const std::vector<uint8_t>& uvm_endorsements_raw)
  {
    // TODO: To be refactored with cose_auth.cpp

    UsefulBufC msg{uvm_endorsements_raw.data(), uvm_endorsements_raw.size()};

    QCBORError qcbor_result;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 outer array");
    }

    uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw std::logic_error("COSE_Sign1 is not tagged");
    }

    struct q_useful_buf_c protected_parameters;
    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    QCBORDecode_EnterMap(&ctx, NULL);

    enum
    {
      ALG_INDEX,
      CONTENT_TYPE_INDEX,
      X5_CHAIN_INDEX,
      ISS_INDEX,
      FEED_INDEX,
      END_INDEX
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[ALG_INDEX].label.int64 = COSE_HEADER_PARAM_ALG;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[CONTENT_TYPE_INDEX].label.int64 =
      COSE_HEADER_PARAM_CONTENT_TYPE;
    header_items[CONTENT_TYPE_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CONTENT_TYPE_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[X5_CHAIN_INDEX].label.int64 = COSE_HEADER_PARAM_X5CHAIN;
    header_items[X5_CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[X5_CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

    auto iss_label = "iss";
    header_items[ISS_INDEX].label.string = UsefulBuf_FromSZ(iss_label);
    header_items[ISS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    auto feed_label = "feed";
    header_items[FEED_INDEX].label.string = UsefulBuf_FromSZ(feed_label);
    header_items[FEED_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[FEED_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to decode protected header");
    }

    ProtectedHeader phdr = {};
    phdr.alg = header_items[ALG_INDEX].val.int64;

    if (header_items[CONTENT_TYPE_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      phdr.content_type =
        qcbor_buf_to_string(header_items[CONTENT_TYPE_INDEX].val.string);
    }

    if (header_items[X5_CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      QCBORItem chain_item = header_items[X5_CHAIN_INDEX];
      size_t array_length = chain_item.val.uCount;

      // TODO: Check length > 0

      if (chain_item.uDataType == QCBOR_TYPE_ARRAY)
      {
        QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_X5CHAIN);
        for (int i = 0; i < array_length; i++)
        {
          QCBORDecode_GetNext(&ctx, &chain_item);
          if (chain_item.uDataType == QCBOR_TYPE_BYTE_STRING)
          {
            phdr.x5_chain.push_back(
              qcbor_buf_to_byte_vector(chain_item.val.string));
          }
        }
        QCBORDecode_ExitArray(&ctx);
      }
    }

    if (header_items[ISS_INDEX].uDataType != QCBOR_TYPE_NONE) // TODO: Throw if
                                                              // this doesn't
                                                              // exist?
    {
      phdr.iss = qcbor_buf_to_string(header_items[ISS_INDEX].val.string);
    }

    if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      phdr.feed = qcbor_buf_to_string(header_items[FEED_INDEX].val.string);
    }

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    return phdr;
  }

  static std::span<const uint8_t> verify_uvm_endorsements_signature(
    const crypto::PublicKeyPtr& leef_cert_pub_key,
    const std::vector<uint8_t>& uvm_endorsements_raw)
  {
    auto verifier = crypto::make_cose_verifier(leef_cert_pub_key);

    std::span<uint8_t> payload;
    if (!verifier->verify(uvm_endorsements_raw, payload))
    {
      throw std::logic_error("Signature verification failed");
    }

    return payload;
  }
}