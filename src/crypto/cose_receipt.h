// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/receipt.h"

#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <span>
#include <string>
#include <vector>

namespace ccf::cose
{
  // COSE header parameter keys
  static constexpr int64_t COSE_HEADER_KEY_ALG = 1;
  static constexpr int64_t COSE_HEADER_KEY_KID = 4;
  static constexpr int64_t COSE_HEADER_KEY_VDP = 396;
  static constexpr int64_t COSE_HEADER_KEY_INCLUSION_PROOFS = -1;

  // Decoded Merkle proof from a COSE receipt unprotected header.
  struct MerkleProof
  {
    std::vector<uint8_t> write_set_digest;
    std::string commit_evidence;
    std::vector<uint8_t> claims_digest;
    // Each element: (direction, hash). direction != 0 means left sibling.
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> path;
  };

  // Result of parsing a COSE receipt's headers.
  struct ReceiptContents
  {
    std::string kid;
    std::vector<MerkleProof> proofs;
  };

  // --- QCBOR helpers ---

  static inline std::vector<uint8_t> qcbor_bstr_to_bytes(const QCBORItem& item)
  {
    return {
      static_cast<const uint8_t*>(item.val.string.ptr),
      static_cast<const uint8_t*>(item.val.string.ptr) + item.val.string.len};
  }

  static inline std::string qcbor_tstr_to_string(const QCBORItem& item)
  {
    return {
      static_cast<const char*>(item.val.string.ptr),
      static_cast<const char*>(item.val.string.ptr) + item.val.string.len};
  }

  // --- Proof decoding ---

  // Decode the leaf components (write set digest, commit evidence, claims
  // digest) from a Merkle proof map that has already been entered.
  static MerkleProof decode_merkle_proof_leaf(QCBORDecodeContext& ctx)
  {
    QCBORDecode_EnterArrayFromMapN(
      &ctx, ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse Merkle proof leaf array");
    }

    QCBORItem item;
    MerkleProof proof;

    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::logic_error("Expected byte string for write_set_digest");
    }
    proof.write_set_digest = qcbor_bstr_to_bytes(item);

    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType != QCBOR_TYPE_TEXT_STRING)
    {
      throw std::logic_error("Expected text string for commit_evidence");
    }
    proof.commit_evidence = qcbor_tstr_to_string(item);

    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::logic_error("Expected byte string for claims_digest");
    }
    proof.claims_digest = qcbor_bstr_to_bytes(item);

    QCBORDecode_ExitArray(&ctx);
    return proof;
  }

  // Decode the path (list of [direction, hash] pairs) from a Merkle proof
  // map that has already been entered. Appends to proof.path.
  static void decode_merkle_proof_path(
    QCBORDecodeContext& ctx, MerkleProof& proof)
  {
    QCBORDecode_EnterArrayFromMapN(
      &ctx, ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse Merkle proof path array");
    }

    for (;;)
    {
      QCBORItem item;
      QCBORDecode_EnterArray(&ctx, &item);
      if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
      {
        break;
      }

      std::pair<int64_t, std::vector<uint8_t>> path_item;

      if (QCBORDecode_GetNext(&ctx, &item) != QCBOR_SUCCESS)
      {
        throw std::logic_error("Failed to parse path direction");
      }
      if (item.uDataType == CBOR_SIMPLEV_TRUE)
      {
        path_item.first = 1;
      }
      else if (item.uDataType == CBOR_SIMPLEV_FALSE)
      {
        path_item.first = 0;
      }
      else
      {
        throw std::logic_error("Invalid CBOR boolean in Merkle proof path");
      }

      if (
        QCBORDecode_GetNext(&ctx, &item) != QCBOR_SUCCESS ||
        item.uDataType != QCBOR_TYPE_BYTE_STRING)
      {
        throw std::logic_error("Failed to parse path hash");
      }
      path_item.second = qcbor_bstr_to_bytes(item);

      proof.path.push_back(path_item);
      QCBORDecode_ExitArray(&ctx);
    }
  }

  // Decode a single bstr-wrapped Merkle proof (leaf + path).
  static MerkleProof decode_merkle_proof(const std::vector<uint8_t>& encoded)
  {
    q_useful_buf_c buf{encoded.data(), encoded.size()};
    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&ctx, NULL);

    auto proof = decode_merkle_proof_leaf(ctx);
    decode_merkle_proof_path(ctx, proof);

    return proof;
  }

  // --- Root recomputation ---

  // Recompute the Merkle root from a decoded proof.
  static std::vector<uint8_t> recompute_root(const MerkleProof& proof)
  {
    auto ce_digest = ccf::crypto::Sha256Hash(proof.commit_evidence);

    if (proof.write_set_digest.size() != ccf::crypto::Sha256Hash::SIZE)
    {
      throw std::logic_error(fmt::format(
        "Unsupported write set digest size: {}",
        proof.write_set_digest.size()));
    }
    if (proof.claims_digest.size() != ccf::crypto::Sha256Hash::SIZE)
    {
      throw std::logic_error(fmt::format(
        "Unsupported claims digest size: {}", proof.claims_digest.size()));
    }

    std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> wsd{
      proof.write_set_digest.data(), ccf::crypto::Sha256Hash::SIZE};
    std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> cd{
      proof.claims_digest.data(), ccf::crypto::Sha256Hash::SIZE};
    auto leaf = ccf::crypto::Sha256Hash(
      ccf::crypto::Sha256Hash::from_span(wsd),
      ce_digest,
      ccf::crypto::Sha256Hash::from_span(cd));

    for (const auto& element : proof.path)
    {
      std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> sibling{
        element.second.data(), ccf::crypto::Sha256Hash::SIZE};
      if (element.first != 0)
      {
        leaf = ccf::crypto::Sha256Hash(
          ccf::crypto::Sha256Hash::from_span(sibling), leaf);
      }
      else
      {
        leaf = ccf::crypto::Sha256Hash(
          leaf, ccf::crypto::Sha256Hash::from_span(sibling));
      }
    }

    return {leaf.h.begin(), leaf.h.end()};
  }

  // --- COSE_Sign1 receipt parsing ---

  // Extract the KID from the COSE_Sign1 protected header.
  // ctx must be positioned at the start of the COSE_Sign1 array elements
  // (i.e. after EnterArray). On return, ctx is positioned after the
  // protected header bstr.
  static std::string extract_kid_from_protected_header(QCBORDecodeContext& ctx)
  {
    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, nullptr);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to enter protected header bstr");
    }

    QCBORDecode_EnterMap(&ctx, nullptr);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse protected header map");
    }

    QCBORItem item;
    QCBORDecode_GetItemInMapN(
      &ctx, COSE_HEADER_KEY_KID, QCBOR_TYPE_BYTE_STRING, &item);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to find KID in protected header");
    }
    auto kid = qcbor_tstr_to_string(item);

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    return kid;
  }

  // Extract inclusion proofs from the COSE_Sign1 unprotected header.
  // ctx must be positioned at the unprotected header (index 1).
  // On return, ctx is positioned after the unprotected header.
  static std::vector<MerkleProof> extract_inclusion_proofs(
    QCBORDecodeContext& ctx)
  {
    QCBORDecode_EnterMap(&ctx, nullptr);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse unprotected header map");
    }

    QCBORDecode_EnterMapFromMapN(&ctx, COSE_HEADER_KEY_VDP);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to find VDP map in unprotected header");
    }

    QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_KEY_INCLUSION_PROOFS);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to find inclusion proofs in VDP map");
    }

    std::vector<MerkleProof> proofs;
    for (;;)
    {
      QCBORItem item;
      if (QCBORDecode_GetNext(&ctx, &item) != QCBOR_SUCCESS)
      {
        break;
      }
      if (item.uDataType != QCBOR_TYPE_BYTE_STRING)
      {
        throw std::logic_error(fmt::format(
          "Expected byte string for encoded proof, got QCBOR type {}",
          item.uDataType));
      }
      proofs.push_back(decode_merkle_proof(qcbor_bstr_to_bytes(item)));
    }

    return proofs;
  }

  // Parse a COSE_Sign1 receipt, extracting the KID and inclusion proofs.
  static ReceiptContents parse_cose_receipt(std::span<const uint8_t> receipt)
  {
    UsefulBufC cose_buf{receipt.data(), receipt.size()};
    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, cose_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 outer array");
    }

    uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw std::logic_error("COSE receipt is not tagged as COSE_Sign1");
    }

    auto kid = extract_kid_from_protected_header(ctx);
    auto proofs = extract_inclusion_proofs(ctx);

    return {std::move(kid), std::move(proofs)};
  }

  // Verify that all proofs in a receipt produce the same Merkle root.
  // Returns the Merkle root. Expects exactly one proof.
  static std::vector<uint8_t> verify_merkle_root(
    const std::vector<MerkleProof>& proofs)
  {
    if (proofs.empty())
    {
      throw std::logic_error("No Merkle proofs found in COSE receipt");
    }

    if (proofs.size() != 1)
    {
      throw std::logic_error(fmt::format(
        "Expected exactly one inclusion proof, got {}", proofs.size()));
    }

    return recompute_root(proofs[0]);
  }

  // Verify that a KID matches the SHA-256 of a service identity
  // certificate's public key.
  static void verify_kid_matches_service_identity(
    const std::string& kid, const std::vector<uint8_t>& service_identity_pem)
  {
    ccf::crypto::Pem pem(service_identity_pem);
    LOG_DEBUG_FMT("Previous service identity PEM:\n{}", pem.str());

    auto cert_der = ccf::crypto::cert_pem_to_der(pem);
    auto pubk_der = ccf::crypto::public_key_der_from_cert(cert_der);
    auto expected_kid = ccf::crypto::Sha256Hash(pubk_der).hex_str();

    if (kid != expected_kid)
    {
      throw std::logic_error(fmt::format(
        "COSE receipt KID ({}) does not match SHA-256 of previous service "
        "identity public key ({})",
        kid,
        expected_kid));
    }
    LOG_DEBUG_FMT(
      "COSE receipt KID matches previous service identity public key");
  }
}
