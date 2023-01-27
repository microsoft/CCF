// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/ds/json.h"
#include "crypto/openssl/cose_verifier.h"
#include "node/did.h"

#include <didx509cpp/didx509cpp.h>
#include <nlohmann/json.hpp>
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

  struct UvmEndorsementsProtectedHeader
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

  static constexpr auto COSE_HEADER_CONTENT_TYPE_APPLICATION_JSON_VALUE =
    "application/json";

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

  static bool is_rsa_alg(int64_t cose_alg)
  {
    return cose_alg == T_COSE_ALGORITHM_PS256 ||
      cose_alg == T_COSE_ALGORITHM_PS384 || cose_alg == T_COSE_ALGORITHM_PS512;
  }

  static UvmEndorsementsProtectedHeader decode_protected_header(
    const std::vector<uint8_t>& uvm_endorsements_raw)
  {
    // Note: Should be refactored with cose_auth.cpp

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
      throw std::logic_error("Failed to parse COSE_Sign1 tag");
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

    UvmEndorsementsProtectedHeader phdr = {};
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

      if (chain_item.uDataType == QCBOR_TYPE_ARRAY)
      {
        QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_X5CHAIN);
        for (size_t i = 0; i < array_length; i++)
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

    if (header_items[ISS_INDEX].uDataType != QCBOR_TYPE_NONE)
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
    const crypto::RSAPublicKeyPtr& leef_cert_pub_key,
    const std::vector<uint8_t>& uvm_endorsements_raw)
  {
    auto verifier = crypto::make_cose_verifier(leef_cert_pub_key);

    std::span<uint8_t> payload;
    if (!verifier->verify(uvm_endorsements_raw, payload))
    {
      throw std::logic_error("Signature verification failed");
    }

    LOG_INFO_FMT("UVM endorsements signature successfully verified");

    return payload;
  }

  static UVMEndorsementsPayload verify_uvm_endorsements(
    const std::vector<uint8_t>& uvm_endorsements_raw)
  {
    auto phdr = decode_protected_header(uvm_endorsements_raw);

    LOG_TRACE_FMT(
      "phdr:: alg:{},content type:{},x5chain:{},iss:{},feed:{}",
      phdr.alg,
      phdr.content_type,
      phdr.x5_chain.size(),
      phdr.iss,
      phdr.feed);

    if (!is_rsa_alg(phdr.alg))
    {
      throw std::logic_error(
        fmt::format("Signature algorithm {} is not expected RSA", phdr.alg));
    }

    // TODO: Will the did always be present as iss?
    const std::string& did = phdr.iss;
    std::string pem_chain;
    for (auto const& c : phdr.x5_chain)
    {
      pem_chain += crypto::cert_der_to_pem(c).str();
    }

    auto did_document_str = didx509::resolve(pem_chain, did);
    did::DIDDocument did_document = nlohmann::json::parse(did_document_str);

    LOG_INFO_FMT("DID document: {}", did_document_str);

    if (did_document.verification_method.empty())
    {
      throw std::logic_error(fmt::format(
        "Could not find verification method for DID document: {}",
        did_document_str));
    }

    crypto::RSAPublicKeyPtr pubk = nullptr;
    for (auto const& vm : did_document.verification_method)
    {
      if (vm.controller == did && vm.public_key_jwk.has_value())
      {
        pubk = crypto::make_rsa_public_key(vm.public_key_jwk.value());
        break;
      }
    }

    if (pubk == nullptr)
    {
      throw std::logic_error(fmt::format(
        "Could not find matching public key for DID {} in {}",
        did,
        did_document_str));
    }

    auto raw_payload =
      verify_uvm_endorsements_signature(pubk, uvm_endorsements_raw);

    if (phdr.content_type != COSE_HEADER_CONTENT_TYPE_APPLICATION_JSON_VALUE)
    {
      throw std::logic_error(fmt::format(
        "Unexpected payload content type {}, expected {}",
        phdr.content_type,
        COSE_HEADER_CONTENT_TYPE_APPLICATION_JSON_VALUE));
    }

    return nlohmann::json::parse(raw_payload);
  }
}