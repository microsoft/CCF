// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <crypto/openssl/cose_sign.h>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
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
    return {reinterpret_cast<const char*>(buf.ptr), buf.len};
  }

  static std::vector<uint8_t> qcbor_buf_to_byte_vector(const UsefulBufC& buf)
  {
    const auto* ptr = static_cast<const uint8_t*>(buf.ptr);
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

  static std::string tstring_to_string(QCBORItem& item)
  {
    return {
      static_cast<const char*>(item.val.string.ptr),
      static_cast<const char*>(item.val.string.ptr) + item.val.string.len};
  }

  static std::pair<std::string /* issuer */, std::string /* subject */>
  extract_iss_sub_from_sig(const std::vector<uint8_t>& cose_sign1)
  {
    QCBORError qcbor_result = QCBOR_SUCCESS;
    QCBORDecodeContext ctx;
    UsefulBufC buf{cose_sign1.data(), cose_sign1.size()};
    QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
    }

    uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw COSEDecodeError("COSE_Sign1 is not tagged");
    }

    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, nullptr);
    QCBORDecode_EnterMap(&ctx, nullptr);

    enum : std::uint8_t
    {
      CWT_CLAIMS_INDEX,
      END_INDEX,
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[CWT_CLAIMS_INDEX].label.int64 = crypto::COSE_PHEADER_KEY_CWT;
    header_items[CWT_CLAIMS_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CWT_CLAIMS_INDEX].uDataType = QCBOR_TYPE_MAP;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode protected header: {}", qcbor_result));
    }

    if (header_items[CWT_CLAIMS_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw COSEDecodeError("Missing CWT claims in COSE_Sign1");
    }

    QCBORDecode_EnterMapFromMapN(&ctx, crypto::COSE_PHEADER_KEY_CWT);
    auto decode_error = QCBORDecode_GetError(&ctx);
    if (decode_error != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode CWT claims: {}", decode_error));
    }

    enum : std::uint8_t
    {
      CWT_ISS_INDEX,
      CWT_SUB_INDEX,
      CWT_END_INDEX,
    };
    QCBORItem cwt_items[CWT_END_INDEX + 1];

    cwt_items[CWT_ISS_INDEX].label.int64 = crypto::COSE_PHEADER_KEY_ISS;
    cwt_items[CWT_ISS_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[CWT_ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    cwt_items[CWT_SUB_INDEX].label.int64 = crypto::COSE_PHEADER_KEY_SUB;
    cwt_items[CWT_SUB_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[CWT_SUB_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    cwt_items[CWT_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, cwt_items);
    decode_error = QCBORDecode_GetError(&ctx);
    if (decode_error != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode CWT claim contents: {}", decode_error));
    }

    if (
      cwt_items[CWT_ISS_INDEX].uDataType != QCBOR_TYPE_NONE &&
      cwt_items[CWT_SUB_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      auto issuer = tstring_to_string(cwt_items[CWT_ISS_INDEX]);
      auto subject = tstring_to_string(cwt_items[CWT_SUB_INDEX]);
      return {issuer, subject};
    }

    throw COSEDecodeError(
      "Missing issuer and subject values in CWT Claims in COSE_Sign1");
  }
}