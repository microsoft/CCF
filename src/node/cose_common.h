// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/hex.h"
#include "ccf/receipt.h"

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
    static constexpr int64_t PARAM_VDP = 396;
    static constexpr int64_t PARAM_MERKLE_PROOFS = -1;

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

  static std::string tstring_to_string(QCBORItem& item)
  {
    return {
      static_cast<const char*>(item.val.string.ptr),
      static_cast<const char*>(item.val.string.ptr) + item.val.string.len};
  }

  struct CwtClaims
  {
    int64_t iat{};
    std::string iss{};
    std::string sub{};
  };

  struct CcfClaims
  {
    std::string txid{};
  };

  struct CcfCoseReceiptPhdr
  {
    int alg{};
    std::vector<uint8_t> kid{};
    CwtClaims cwt{};
    CcfClaims ccf{};
    int vds{};
  };

  struct Leaf
  {
    std::vector<uint8_t> write_set_digest;
    std::string commit_evidence;
    std::vector<uint8_t> claims_digest;
  };

  struct MerkleProof
  {
    Leaf leaf;
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> path;
  };

  struct CcfCoseReceipt
  {
    CcfCoseReceiptPhdr phdr;
    std::vector<uint8_t> merkle_root;
  };

  static std::vector<uint8_t> recompute_merkle_root(const MerkleProof& proof)
  {
    auto ce_digest = ccf::crypto::Sha256Hash(proof.leaf.commit_evidence);

    if (proof.leaf.write_set_digest.size() != ccf::crypto::Sha256Hash::SIZE)
    {
      throw COSEDecodeError(fmt::format(
        "Unsupported write set digest size in Merkle proof leaf: {}",
        proof.leaf.write_set_digest.size()));
    }
    if (proof.leaf.claims_digest.size() != ccf::crypto::Sha256Hash::SIZE)
    {
      throw COSEDecodeError(fmt::format(
        "Unsupported claims digest size in Merkle proof leaf: {}",
        proof.leaf.claims_digest.size()));
    }

    std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> wsd{
      proof.leaf.write_set_digest.data(), ccf::crypto::Sha256Hash::SIZE};
    std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> cd{
      proof.leaf.claims_digest.data(), ccf::crypto::Sha256Hash::SIZE};
    auto leaf_digest = ccf::crypto::Sha256Hash(
      ccf::crypto::Sha256Hash::from_span(wsd),
      ce_digest,
      ccf::crypto::Sha256Hash::from_span(cd));

    for (const auto& element : proof.path)
    {
      if (element.first)
      {
        std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> sibling{
          element.second.data(), ccf::crypto::Sha256Hash::SIZE};
        leaf_digest = ccf::crypto::Sha256Hash(
          ccf::crypto::Sha256Hash::from_span(sibling), leaf_digest);
      }
      else
      {
        std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> sibling{
          element.second.data(), ccf::crypto::Sha256Hash::SIZE};
        leaf_digest = ccf::crypto::Sha256Hash(
          leaf_digest, ccf::crypto::Sha256Hash::from_span(sibling));
      }
    }

    return {leaf_digest.h.begin(), leaf_digest.h.end()};
  }

  static void decode_receipt_top_level_phdr(
    QCBORDecodeContext& ctx, CcfCoseReceiptPhdr& phdr)
  {
    enum
    {
      ALG_INDEX,
      KID_INDEX,
      CWT_INDEX,
      VDS_INDEX,
      END_INDEX,
    };

    QCBORItem header_items[END_INDEX + 1];

    header_items[ALG_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_ALG;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[KID_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_ID;
    header_items[KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    header_items[CWT_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_CWT;
    header_items[CWT_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CWT_INDEX].uDataType = QCBOR_TYPE_MAP;

    header_items[VDS_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_VDS;
    header_items[VDS_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[VDS_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);

    auto qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw ccf::cose::COSEDecodeError(fmt::format(
        "Failed to decode protected header: {}",
        qcbor_err_to_str(qcbor_result)));
    }

    if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError(
        "COSE receipt missing 'alg' in protected header");
    }
    phdr.alg = header_items[ALG_INDEX].val.int64;

    if (header_items[KID_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError(
        "COSE receipt missing 'kid' in protected header");
    }
    phdr.kid =
      ccf::cose::qcbor_buf_to_byte_vector(header_items[KID_INDEX].val.string);

    if (header_items[VDS_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError(
        "COSE receipt missing 'vds' in protected header");
    }
    phdr.vds = header_items[VDS_INDEX].val.int64;

    if (phdr.vds != ccf::crypto::COSE_PHEADER_VDS_MERKLE_TREE)
    {
      throw ccf::cose::COSEDecodeError(fmt::format(
        "Expected VDS={} (Merkle tree), got {}",
        ccf::crypto::COSE_PHEADER_VDS_MERKLE_TREE,
        phdr.vds));
    }
  }

  static void decode_cwt_claims(QCBORDecodeContext& ctx, CwtClaims& cwt)
  {
    QCBORDecode_EnterMapFromMapN(&ctx, crypto::COSE_PHEADER_KEY_CWT);
    auto decode_error = QCBORDecode_GetError(&ctx);
    if (decode_error != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode CWT claims: {}", decode_error));
    }

    enum
    {
      IAT_INDEX,
      ISS_INDEX,
      SUB_INDEX,
      END_CWT_INDEX,
    };

    QCBORItem cwt_items[END_CWT_INDEX + 1];

    cwt_items[IAT_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_IAT;
    cwt_items[IAT_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[IAT_INDEX].uDataType = QCBOR_TYPE_INT64;

    cwt_items[ISS_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_ISS;
    cwt_items[ISS_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    cwt_items[SUB_INDEX].label.int64 = ccf::crypto::COSE_PHEADER_KEY_SUB;
    cwt_items[SUB_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[SUB_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    cwt_items[END_CWT_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, cwt_items);
    decode_error = QCBORDecode_GetError(&ctx);
    if (decode_error != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode CWT claims: {}", decode_error));
    }

    if (cwt_items[IAT_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError("CWT claims missing 'iat' field");
    }
    cwt.iat = cwt_items[IAT_INDEX].val.int64;

    if (cwt_items[ISS_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError("CWT claims missing 'iss' field");
    }
    cwt.iss = tstring_to_string(cwt_items[ISS_INDEX]);

    if (cwt_items[SUB_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError("CWT claims missing 'sub' field");
    }
    cwt.sub = tstring_to_string(cwt_items[SUB_INDEX]);

    QCBORDecode_ExitMap(&ctx);
  }

  static void decode_ccf_claims(QCBORDecodeContext& ctx, CcfClaims& ccf)
  {
    QCBORDecode_EnterMapFromMapSZ(
      &ctx, ccf::crypto::COSE_PHEADER_KEY_CCF.c_str());
    auto decode_error = QCBORDecode_GetError(&ctx);
    if (decode_error != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode CCF claims: {}", decode_error));
    }

    enum
    {
      TXID_INDEX,
      END_CCF_INDEX,
    };

    QCBORItem ccf_items[END_CCF_INDEX + 1];

    ccf_items[TXID_INDEX].label.string = UsefulBufC{
      ccf::crypto::COSE_PHEADER_KEY_TXID.data(),
      ccf::crypto::COSE_PHEADER_KEY_TXID.size()};
    ccf_items[TXID_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    ccf_items[TXID_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    ccf_items[END_CCF_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, ccf_items);
    decode_error = QCBORDecode_GetError(&ctx);
    if (decode_error != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode CCF claims: {}", decode_error));
    }

    if (ccf_items[TXID_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw ccf::cose::COSEDecodeError("CCF claims missing 'txid' field");
    }
    ccf.txid = tstring_to_string(ccf_items[TXID_INDEX]);

    QCBORDecode_ExitMap(&ctx);
  }

  static CcfCoseReceiptPhdr decode_ccf_receipt_phdr(QCBORDecodeContext& ctx)
  {
    QCBORDecode_EnterBstrWrapped(&ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(&ctx, NULL);

    CcfCoseReceiptPhdr phdr{};

    decode_receipt_top_level_phdr(ctx, phdr);
    decode_cwt_claims(ctx, phdr.cwt);
    decode_ccf_claims(ctx, phdr.ccf);

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    return phdr;
  }

  /* Expects QCBORDecodeContext to be at 'uhdr'. */
  static std::vector<MerkleProof> decode_merkle_proofs(QCBORDecodeContext& ctx)
  {
    QCBORDecode_EnterMap(&ctx, NULL);
    auto err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to enter unprotected header map: {}", err));
    }

    QCBORDecode_EnterMapFromMapN(&ctx, headers::PARAM_VDP);
    err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to enter Merkle proofs map: {}", err));
    }

    QCBORDecode_EnterArrayFromMapN(&ctx, headers::PARAM_MERKLE_PROOFS);
    err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to enter Merkle proofs array: {}", err));
    }

    std::vector<uint8_t> root;
    std::vector<MerkleProof> proofs;
    for (;;)
    {
      QCBORDecode_EnterBstrWrapped(&ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
      err = QCBORDecode_GetError(&ctx);
      if (err != QCBOR_SUCCESS)
      {
        err = QCBORDecode_GetAndResetError(&ctx);
        if (err != QCBOR_ERR_NO_MORE_ITEMS)
        {
          throw COSEDecodeError(fmt::format(
            "Expected NO_MORE_ITEMS after reading Merkle proofs, got {}", err));
        }
        break;
      }

      QCBORDecode_EnterMap(&ctx, NULL);
      err = QCBORDecode_GetError(&ctx);
      if (err != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(fmt::format("Failed to enter leaf map: {}", err));
      }

      QCBORDecode_EnterArrayFromMapN(
        &ctx, ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL);

      QCBORItem item;
      MerkleProof proof;

      QCBORDecode_GetNext(&ctx, &item);
      if (item.uDataType != QCBOR_TYPE_BYTE_STRING)
      {
        throw COSEDecodeError(fmt::format(
          "Expected byte string for write_set_digest, got {}", item.uDataType));
      }
      proof.leaf.write_set_digest =
        ccf::cose::qcbor_buf_to_byte_vector(item.val.string);

      QCBORDecode_GetNext(&ctx, &item);
      if (item.uDataType != QCBOR_TYPE_TEXT_STRING)
      {
        throw COSEDecodeError(fmt::format(
          "Expected text string for commit_evidence, got {}", item.uDataType));
      }

      proof.leaf.commit_evidence =
        ccf::cose::qcbor_buf_to_string(item.val.string);

      QCBORDecode_GetNext(&ctx, &item);
      if (item.uDataType != QCBOR_TYPE_BYTE_STRING)
      {
        throw COSEDecodeError(fmt::format(
          "Expected byte string for claims_digest, got {}", item.uDataType));
      }

      proof.leaf.claims_digest =
        ccf::cose::qcbor_buf_to_byte_vector(item.val.string);

      QCBORDecode_ExitArray(&ctx);

      QCBORDecode_EnterArrayFromMapN(
        &ctx, ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL);
      err = QCBORDecode_GetError(&ctx);
      if (err != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to enter path array: {}", err));
      }

      for (;;)
      {
        QCBORDecode_EnterArray(&ctx, &item);
        if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
        {
          err = QCBORDecode_GetAndResetError(&ctx);
          if (err != QCBOR_ERR_NO_MORE_ITEMS)
          {
            throw COSEDecodeError(fmt::format(
              "Expected NO_MORE_ITEMS after reading path, got {}", err));
          }
          break;
        }

        std::pair<int64_t, std::vector<uint8_t>> path_item;

        err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(
            fmt::format("Failed to get path direction item: {}", err));
        }

        if (item.uDataType == CBOR_SIMPLEV_TRUE)
        {
          path_item.first = true;
        }
        else if (item.uDataType == CBOR_SIMPLEV_FALSE)
        {
          path_item.first = false;
        }
        else
        {
          // Not a valid CBOR boolean
          throw COSEDecodeError(fmt::format(
            "Invalid path direction in Merkle proof: {}", item.uDataType));
        }

        err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(
            fmt::format("Failed to get path hash item: {}", err));
        }
        if (item.uDataType != QCBOR_TYPE_BYTE_STRING)
        {
          throw COSEDecodeError(fmt::format(
            "Expected byte string for path hash, got {}", item.uDataType));
        }

        path_item.second = ccf::cose::qcbor_buf_to_byte_vector(item.val.string);
        proof.path.push_back(path_item);

        QCBORDecode_ExitArray(&ctx);
        err = QCBORDecode_GetError(&ctx);
        if (err != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(
            fmt::format("Failed to exit path item array: {}", err));
        }
      }

      QCBORDecode_ExitArray(&ctx); // path
      err = QCBORDecode_GetError(&ctx);
      if (err != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to exit path array: {}", err));
      }

      QCBORDecode_ExitMap(&ctx); // proof
      err = QCBORDecode_GetError(&ctx);
      if (err != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(fmt::format("Failed to exit proof map: {}", err));
      }

      QCBORDecode_ExitBstrWrapped(&ctx); // wrapped proof
      err = QCBORDecode_GetError(&ctx);
      if (err != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to exit wrapped proof: {}", err));
      }

      proofs.push_back(proof);
    }

    QCBORDecode_ExitArray(&ctx); // proofs array
    err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to exit proofs array: {}", err));
    }

    QCBORDecode_ExitMap(&ctx); // VDP
    err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(fmt::format("Failed to exit VDP map: {}", err));
    }

    QCBORDecode_ExitMap(&ctx); // uhdr
    err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(fmt::format("Failed to exit uhdr map: {}", err));
    }

    return proofs;
  }

  static CcfCoseReceipt decode_ccf_receipt(
    const std::vector<uint8_t>& cose_sign1, bool recompute_root)
  {
    QCBORError qcbor_result;
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

    CcfCoseReceipt receipt;

    receipt.phdr = decode_ccf_receipt_phdr(ctx);

    if (recompute_root)
    {
      auto proofs = decode_merkle_proofs(ctx);
      if (proofs.empty())
      {
        throw COSEDecodeError("No Merkle proofs found in COSE receipt");
      }

      receipt.merkle_root = recompute_merkle_root(proofs[0]);
      for (size_t i = 1; i < proofs.size(); ++i)
      {
        auto root = recompute_merkle_root(proofs[i]);
        if (root != receipt.merkle_root)
        {
          throw COSEDecodeError(
            "Inconsistent Merkle roots computed from COSE receipt proofs");
        }
      }
    }

    return receipt;
  }
}