// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/hex.h"
#include "ccf/receipt.h"
#include "crypto/cbor_helpers.h"

#include <crypto/cbor_tags.h>
#include <crypto/cose.h>
#include <crypto/cose_utils.h>
#include <optional>
#include <string>
#include <string_view>
#include <tav/cbor.hpp>
#include <variant>

namespace ccf::cose
{
  struct Sign1ProtectedHeader
  {
    int64_t alg{};
    std::optional<std::variant<int64_t, std::string>> cty;
    std::vector<std::vector<uint8_t>> x5chain;
    CwtClaims cwt;
  };

  static Sign1ProtectedHeader decode_sign1_protected_header(
    const tav::cbor::Value& phdr)
  {
    using namespace tav::cbor;
    Sign1ProtectedHeader hdr;

    hdr.alg = rethrow_with_msg(
      [&]() {
        return phdr.map_at(make_signed(ccf::cose::header::iana::ALG))
          .as_signed();
      },
      fmt::format(
        "Parse protected header alg({})", ccf::cose::header::iana::ALG));

    try
    {
      const auto& cty =
        phdr.map_at(make_signed(ccf::cose::header::iana::CONTENT_TYPE));
      try
      {
        hdr.cty = std::string(cty.as_string());
      }
      catch (const DecodeError&)
      {
        hdr.cty = cty.as_signed();
      }
    }
    catch (const DecodeError& err)
    {
      std::ignore = err; // optional field
    }

    hdr.x5chain = rethrow_with_msg(
      [&]() {
        const auto& x5chain_val =
          phdr.map_at(make_signed(ccf::cose::header::iana::X5CHAIN));
        return ccf::cose::utils::parse_x5chain(x5chain_val);
      },
      fmt::format(
        "Parse protected header x5chain({})",
        ccf::cose::header::iana::X5CHAIN));

    decode_cwt_claims(phdr, hdr.cwt);

    return hdr;
  }

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
    std::vector<uint8_t> claims_digest;
  };

  static void validate_sha256_bytes(
    std::span<const uint8_t> bytes, std::string_view field)
  {
    if (bytes.size() != ccf::crypto::Sha256Hash::SIZE)
    {
      throw COSEDecodeError(fmt::format(
        "Unsupported {} size: {} (expected {})",
        field,
        bytes.size(),
        ccf::crypto::Sha256Hash::SIZE));
    }
  }

  static ccf::crypto::Sha256Hash sha256_from_bytes(
    std::span<const uint8_t> bytes, std::string_view field)
  {
    validate_sha256_bytes(bytes, field);
    const std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> fixed{
      bytes.data(), ccf::crypto::Sha256Hash::SIZE};
    return ccf::crypto::Sha256Hash::from_span(fixed);
  }

  static std::vector<uint8_t> recompute_merkle_root(const MerkleProof& proof)
  {
    auto ce_digest = ccf::crypto::Sha256Hash(proof.leaf.commit_evidence);

    auto leaf_digest = ccf::crypto::Sha256Hash(
      sha256_from_bytes(
        proof.leaf.write_set_digest, "Merkle proof write set digest"),
      ce_digest,
      sha256_from_bytes(
        proof.leaf.claims_digest, "Merkle proof claims digest"));

    for (const auto& element : proof.path)
    {
      const auto sibling =
        sha256_from_bytes(element.second, "Merkle proof sibling");
      if (element.first != 0)
      {
        leaf_digest = ccf::crypto::Sha256Hash(sibling, leaf_digest);
      }
      else
      {
        leaf_digest = ccf::crypto::Sha256Hash(leaf_digest, sibling);
      }
    }

    return {leaf_digest.h.begin(), leaf_digest.h.end()};
  }

  static void validate_array(
    const tav::cbor::Value& value, size_t size, std::string_view field)
  {
    if (value.kind() != tav::cbor::Kind::ARRAY || value.size() != size)
    {
      throw COSEDecodeError(
        fmt::format("{} must be an array of {} elements", field, size));
    }
  }

  static std::vector<std::pair<int64_t, std::vector<uint8_t>>>
  decode_proof_path(const tav::cbor::Value& path)
  {
    using namespace tav::cbor;

    if (path.kind() != Kind::ARRAY)
    {
      throw COSEDecodeError("Merkle proof path must be an array");
    }

    std::vector<std::pair<int64_t, std::vector<uint8_t>>> decoded;
    for (size_t i = 0; i < path.size(); ++i)
    {
      const auto link = path.array_at(i);
      validate_array(link, 2, "Merkle proof path element");
      const auto left = simple_to_boolean(link.array_at(0).as_simple());
      const auto digest = link.array_at(1).as_bytes();
      validate_sha256_bytes(digest, "Merkle proof sibling");
      decoded.emplace_back(
        left, std::vector<uint8_t>(digest.begin(), digest.end()));
    }

    return decoded;
  }

  static void decode_ccf_claims(const tav::cbor::Value& cbor, CcfClaims& claims)
  {
    using namespace tav::cbor;

    const auto ccf_claims = rethrow_with_msg(
      [&]() {
        return cbor.map_at(make_string(ccf::cose::header::custom::CCF_V1));
      },
      "Parse CCF claims map");

    claims.txid = rethrow_with_msg(
      [&]() {
        return ccf_claims.map_at(make_string(ccf::cose::header::custom::TX_ID))
          .as_string();
      },
      fmt::format(
        "Parse CCF claims TxID ({}) field", ccf::cose::header::custom::TX_ID));
  }

  static CcfCoseReceiptPhdr decode_ccf_receipt_phdr(tav::cbor::Value& cbor)
  {
    using namespace tav::cbor;

    CcfCoseReceiptPhdr phdr{};

    phdr.alg = rethrow_with_msg(
      [&]() {
        return cbor.map_at(make_signed(ccf::cose::header::iana::ALG))
          .as_signed();
      },
      fmt::format(
        "Parse protected header alg({})", ccf::cose::header::iana::ALG));

    rethrow_with_msg(
      [&]() {
        const auto& bytes =
          cbor.map_at(make_signed(ccf::cose::header::iana::KID)).as_bytes();
        phdr.kid.assign(bytes.begin(), bytes.end());
      },
      fmt::format(
        "Parse protected header kid({})", ccf::cose::header::iana::KID));

    const auto vds = rethrow_with_msg(
      [&]() {
        return cbor.map_at(make_signed(ccf::cose::header::iana::VDS))
          .as_signed();
      },
      fmt::format(
        "Parse protected header vds({})", ccf::cose::header::iana::VDS));

    if (vds != ccf::cose::value::CCF_LEDGER_SHA256)
    {
      throw COSEDecodeError(
        fmt::format("Unsupported vds value ({}) in protected header", vds));
    }

    phdr.vds = static_cast<int>(vds);

    decode_cwt_claims(cbor, phdr.cwt);
    decode_ccf_claims(cbor, phdr.ccf);

    return phdr;
  }

  static std::vector<MerkleProof> decode_merkle_proofs(
    const tav::cbor::Value& cbor)
  {
    using namespace tav::cbor;

    validate_array(cbor, 4, "COSE_Sign1");
    if (
      cbor.array_at(2).kind() != Kind::SIMPLE ||
      cbor.array_at(2).as_simple() != SimpleValue::Null)
    {
      throw COSEDecodeError("COSE receipt payload must be detached");
    }

    const auto uhdr = rethrow_with_msg(
      [&]() { return cbor.array_at(1); }, "Parse unprotected header map");

    const auto vdp = rethrow_with_msg(
      [&]() { return uhdr.map_at(make_signed(ccf::cose::header::iana::VDP)); },
      fmt::format("Parse vdp() map", ccf::cose::header::iana::VDP));

    // Value::empty() checks handle ownership, not collection length.
    const auto proof_types = vdp.kind() == Kind::MAP ? vdp.size() : 0;
    if (proof_types == 0 || proof_types > 2)
    {
      throw COSEDecodeError("Invalid verifiable proofs map");
    }

    constexpr int64_t consistency_proofs_label = -2;
    bool has_consistency_proofs = false;
    for (size_t i = 0; i < proof_types; ++i)
    {
      const auto key = vdp.map_key_at(i).as_signed();
      if (key == consistency_proofs_label)
      {
        has_consistency_proofs = true;
      }
      else if (key != ccf::cose::header::iana::INCLUSION_PROOFS)
      {
        throw COSEDecodeError("Unsupported verifiable proof type");
      }

      const auto array = vdp.map_value_at(i);
      const auto proof_count = array.kind() == Kind::ARRAY ? array.size() : 0;
      if (proof_count == 0)
      {
        throw COSEDecodeError("Proofs must be a non-empty array");
      }
    }

    const auto proofs_array = rethrow_with_msg(
      [&]() {
        return vdp.map_at(
          make_signed(ccf::cose::header::iana::INCLUSION_PROOFS));
      },
      "Parse inclusion proofs");

    std::vector<MerkleProof> proofs;

    const auto proof_count = rethrow_with_msg(
      [&]() {
        const auto count = proofs_array.size();
        if (count == 0)
        {
          throw DecodeError(Error::DECODE_FAILED, "Empty proofs array");
        }

        return count;
      },
      "Check proofs array");

    for (size_t i = 0; i < proof_count; ++i)
    {
      auto cbor_proof = rethrow_with_msg(
        [&]() { return nondet_parse(proofs_array.array_at(i).as_bytes()); },
        "Parse an encoded proof");

      if (cbor_proof.kind() != Kind::MAP || cbor_proof.size() != 2)
      {
        throw COSEDecodeError(
          "Inclusion proof must be a map with leaf and path");
      }

      const auto leaf = rethrow_with_msg(
        [&]() {
          return cbor_proof.map_at(
            make_signed(ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL));
        },
        "Parse proof: leaf");

      validate_array(leaf, 3, "Merkle proof leaf");
      MerkleProof proof;

      rethrow_with_msg(
        [&]() {
          const auto& bytes =
            leaf.array_at(ccf::MerkleProofPathBranch::LEFT).as_bytes();
          validate_sha256_bytes(bytes, "Merkle proof write set digest");
          proof.leaf.write_set_digest.assign(bytes.begin(), bytes.end());
        },
        "Parse leaf at wsd");

      proof.leaf.commit_evidence = rethrow_with_msg(
        [&]() {
          return leaf.array_at(ccf::MerkleProofPathBranch::RIGHT).as_string();
        },
        "Parse leaf at ce");

      if (
        proof.leaf.commit_evidence.empty() ||
        proof.leaf.commit_evidence.size() > 1024)
      {
        throw COSEDecodeError(
          "Merkle proof commit evidence must contain 1 to 1024 UTF-8 bytes");
      }

      rethrow_with_msg(
        [&]() {
          const auto& bytes = leaf.array_at(2).as_bytes();
          validate_sha256_bytes(bytes, "Merkle proof claims digest");
          proof.leaf.claims_digest.assign(bytes.begin(), bytes.end());
        },
        "Parse leaf at cd");

      const auto cbor_path = rethrow_with_msg(
        [&]() {
          return cbor_proof.map_at(
            make_signed(ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL));
        },
        "Parse proof: path");

      proof.path = decode_proof_path(cbor_path);

      proofs.push_back(proof);
    }

    if (has_consistency_proofs)
    {
      const auto consistency_proofs =
        vdp.map_at(make_signed(consistency_proofs_label));
      std::vector<std::vector<uint8_t>> newer_roots;
      for (size_t i = 0; i < consistency_proofs.size(); ++i)
      {
        const auto proof =
          nondet_parse(consistency_proofs.array_at(i).as_bytes());
        if (proof.kind() != Kind::MAP || proof.size() != 2)
        {
          throw COSEDecodeError(
            "Consistency proof must be a map with anchor and path");
        }

        auto newer =
          sha256_from_bytes(proof.map_at(make_signed(1)).as_bytes(), "anchor");
        const auto path = decode_proof_path(proof.map_at(make_signed(2)));
        if (path.empty() || path.front().first != 0)
        {
          throw COSEDecodeError(
            "Consistency proof must start with a right sibling");
        }

        for (const auto& [left, digest] : path)
        {
          const auto sibling = sha256_from_bytes(digest, "sibling");
          newer = left != 0 ? ccf::crypto::Sha256Hash(sibling, newer) :
                              ccf::crypto::Sha256Hash(newer, sibling);
        }

        newer_roots.emplace_back(newer.h.begin(), newer.h.end());
      }

      const auto root = recompute_merkle_root(proofs.front());
      for (const auto& newer : newer_roots)
      {
        if (newer != root)
        {
          throw COSEDecodeError(
            "Inconsistent Merkle roots computed from inclusion and consistency "
            "proofs");
        }
      }
    }

    return proofs;
  }

  static CcfCoseReceipt decode_ccf_receipt(
    const std::vector<uint8_t>& cose_sign1, bool recompute_root)
  {
    using namespace tav::cbor;

    auto cose_cbor = rethrow_with_msg(
      [&]() { return nondet_parse(cose_sign1); }, "Parse COSE CBOR");

    const auto cose_envelope = rethrow_with_msg(
      [&]() { return cose_cbor.tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");
    validate_array(cose_envelope, 4, "COSE_Sign1");

    const auto phdr_raw = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return nondet_parse(phdr_raw.as_bytes()); },
      "Parse protected header");

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
      receipt.claims_digest = proofs[0].leaf.claims_digest;
      for (size_t i = 1; i < proofs.size(); ++i)
      {
        auto root = recompute_merkle_root(proofs[i]);
        if (root != receipt.merkle_root)
        {
          throw COSEDecodeError(
            "Inconsistent Merkle roots computed from COSE receipt proofs");
        }
        if (proofs[i].leaf.claims_digest != receipt.claims_digest)
        {
          throw COSEDecodeError(fmt::format(
            "Claims from proofs don't match: {} != {}",
            ds::to_hex(receipt.claims_digest),
            ds::to_hex(proofs[i].leaf.claims_digest)));
        }
      }
    }

    return receipt;
  }
}