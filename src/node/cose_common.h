// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/hex.h"
#include "ccf/receipt.h"

#include <crypto/cbor.h>
#include <crypto/cose.h>
#include <crypto/openssl/cose_sign.h>
#include <stdexcept>
#include <string>

namespace ccf::cose
{

  using Signature = std::span<const uint8_t>;

  static bool is_ecdsa_alg(int64_t cose_alg)
  {
    // https://www.iana.org/assignments/cose/cose.xhtml
    constexpr int COSE_ALGORITHM_ES256 = -7;
    constexpr int COSE_ALGORITHM_ES384 = -35;
    constexpr int COSE_ALGORITHM_ES512 = -36;
    return cose_alg == COSE_ALGORITHM_ES256 ||
      cose_alg == COSE_ALGORITHM_ES384 || cose_alg == COSE_ALGORITHM_ES512;
  }

  static bool is_rsa_alg(int64_t cose_alg)
  {
    // https: // www.iana.org/assignments/cose/cose.xhtml
    constexpr int COSE_ALGORITHM_PS256 = -37;
    constexpr int COSE_ALGORITHM_PS384 = -38;
    constexpr int COSE_ALGORITHM_PS512 = -39;
    return cose_alg == COSE_ALGORITHM_PS256 ||
      cose_alg == COSE_ALGORITHM_PS384 || cose_alg == COSE_ALGORITHM_PS512;
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

  struct CwtClaims
  {
    int64_t iat{};
    std::string iss;
    std::string sub;
  };

  struct CcfClaims
  {
    std::string txid;
  };

  struct CcfCoseReceiptPhdr
  {
    int alg{};
    std::vector<uint8_t> kid;
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
      if (element.first != 0)
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

  static void decode_cwt_claims(const ccf::cbor::Value& cbor, CwtClaims& claims)
  {
    using namespace ccf::cbor;

    const auto& cwt_claims = rethrow_with_msg(
      [&]() -> auto& {
        return cbor->map_at(make_signed(ccf::cose::header::iana::CWT_CLAIMS));
      },
      "Parse CWT claims map");

    claims.iat = rethrow_with_msg(
      [&]() {
        return cwt_claims->map_at(make_signed(ccf::cwt::header::iana::IAT))
          ->as_signed();
      },
      fmt::format(
        "Parse CWT claim sub({}) field", ccf::cwt::header::iana::IAT));

    claims.iss = rethrow_with_msg(
      [&]() {
        return cwt_claims->map_at(make_signed(ccf::cwt::header::iana::ISS))
          ->as_string();
      },
      fmt::format(
        "Parse CWT claim iss({}) field", ccf::cwt::header::iana::ISS));

    claims.sub = rethrow_with_msg(
      [&]() {
        return cwt_claims->map_at(make_signed(ccf::cwt::header::iana::SUB))
          ->as_string();
      },
      fmt::format(
        "Parse CWT claim sub({}) field", ccf::cwt::header::iana::SUB));
  }

  static void decode_ccf_claims(const ccf::cbor::Value& cbor, CcfClaims& claims)
  {
    using namespace ccf::cbor;

    const auto& ccf_claims = rethrow_with_msg(
      [&]() -> auto& {
        return cbor->map_at(make_string(ccf::cose::header::custom::CCF_V1));
      },
      "Parse CCF claims map");

    claims.txid = rethrow_with_msg(
      [&]() {
        return ccf_claims->map_at(make_string(ccf::cose::header::custom::TX_ID))
          ->as_string();
      },
      fmt::format(
        "Parse CCF claims TxID ({}) field", ccf::cose::header::custom::TX_ID));
  }

  static CcfCoseReceiptPhdr decode_ccf_receipt_phdr(ccf::cbor::Value& cbor)
  {
    using namespace ccf::cbor;

    CcfCoseReceiptPhdr phdr{};

    phdr.alg = rethrow_with_msg(
      [&]() {
        return cbor->map_at(make_signed(ccf::cose::header::iana::ALG))
          ->as_signed();
      },
      fmt::format(
        "Parse protected header alg({})", ccf::cose::header::iana::ALG));

    rethrow_with_msg(
      [&]() {
        const auto& bytes =
          cbor->map_at(make_signed(ccf::cose::header::iana::KID))->as_bytes();
        phdr.kid.assign(bytes.begin(), bytes.end());
      },
      fmt::format(
        "Parse protected header kid({})", ccf::cose::header::iana::KID));

    phdr.vds = rethrow_with_msg(
      [&]() {
        return cbor->map_at(make_signed(ccf::cose::header::iana::VDS))
          ->as_signed();
      },
      fmt::format(
        "Parse protected header vds({})", ccf::cose::header::iana::VDS));

    if (phdr.vds != ccf::cose::value::CCF_LEDGER_SHA256)
    {
      throw COSEDecodeError(fmt::format(
        "Unsupported vds value ({}) in protected header", phdr.vds));
    }

    decode_cwt_claims(cbor, phdr.cwt);
    decode_ccf_claims(cbor, phdr.ccf);

    return phdr;
  }

  static std::vector<MerkleProof> decode_merkle_proofs(
    const ccf::cbor::Value& cbor)
  {
    using namespace ccf::cbor;

    const auto& uhdr = rethrow_with_msg(
      [&]() -> auto& { return cbor->array_at(1); },
      "Parse unprotected header map");

    const auto& vdp = rethrow_with_msg(
      [&]() -> auto& {
        return uhdr->map_at(make_signed(ccf::cose::header::iana::VDP));
      },
      fmt::format("Parse vdp() map", ccf::cose::header::iana::VDP));

    const auto& proofs_array = rethrow_with_msg(
      [&]() -> auto& {
        return vdp->map_at(
          make_signed(ccf::cose::header::iana::INCLUSION_PROOFS));
      },
      "Parse inclusion proofs");

    std::vector<MerkleProof> proofs;

    rethrow_with_msg(
      [&]() {
        if (proofs_array->size() == 0)
        {
          throw CBORDecodeError(Error::DECODE_FAILED, "Empty proofs array");
        }
      },
      "Check proofs array");

    for (size_t i = 0; i < proofs_array->size(); ++i)
    {
      auto cbor_proof = rethrow_with_msg(
        [&]() { return parse(proofs_array->array_at(i)->as_bytes()); },
        "Parse an encoded proof");

      const auto& leaf = rethrow_with_msg(
        [&]() -> auto& {
          return cbor_proof->map_at(
            make_signed(ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL));
        },
        "Parse proof: leaf");

      MerkleProof proof;

      rethrow_with_msg(
        [&]() {
          const auto& bytes =
            leaf->array_at(ccf::MerkleProofPathBranch::LEFT)->as_bytes();
          proof.leaf.write_set_digest.assign(bytes.begin(), bytes.end());
        },
        "Parse leaf at wsd");

      proof.leaf.commit_evidence = rethrow_with_msg(
        [&]() {
          return leaf->array_at(ccf::MerkleProofPathBranch::RIGHT)->as_string();
        },
        "Parse leaf at ce");

      rethrow_with_msg(
        [&]() {
          const auto& bytes = leaf->array_at(2)->as_bytes();
          proof.leaf.claims_digest.assign(bytes.begin(), bytes.end());
        },
        "Parse leaf at cd");

      const auto& cbor_path = rethrow_with_msg(
        [&]() -> auto& {
          return cbor_proof->map_at(
            make_signed(ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL));
        },
        "Parse proof: path");

      rethrow_with_msg(
        [&]() {
          if (cbor_path->size() == 0)
          {
            throw CBORDecodeError(Error::DECODE_FAILED, "Empty path");
          }
        },
        "Check proof: path");

      for (size_t j = 0; j < cbor_path->size(); j++)
      {
        std::pair<int64_t, std::vector<uint8_t>> path_item;
        const auto& link = rethrow_with_msg(
          [&]() -> auto& { return cbor_path->array_at(j); }, "Parse path link");

        path_item.first = static_cast<int64_t>(rethrow_with_msg(
          [&]() { return simple_to_boolean(link->array_at(0)->as_simple()); },
          "Parse path element at direction"));
        rethrow_with_msg(
          [&]() {
            const auto& bytes = link->array_at(1)->as_bytes();
            path_item.second.assign(bytes.begin(), bytes.end());
          },
          "Parse path element at hash");
        proof.path.push_back(path_item);
      }

      proofs.push_back(proof);
    }

    return proofs;
  }

  static CcfCoseReceipt decode_ccf_receipt(
    const std::vector<uint8_t>& cose_sign1, bool recompute_root)
  {
    using namespace ccf::cbor;

    auto cose_cbor =
      rethrow_with_msg([&]() { return parse(cose_sign1); }, "Parse COSE CBOR");

    const auto& cose_envelope = rethrow_with_msg(
      [&]() -> auto& { return cose_cbor->tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");

    const auto& phdr_raw = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return parse(phdr_raw->as_bytes()); }, "Parse protected header");

    CcfCoseReceipt receipt;

    receipt.phdr = decode_ccf_receipt_phdr(phdr);

    if (recompute_root)
    {
      auto proofs = decode_merkle_proofs(cose_envelope);
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