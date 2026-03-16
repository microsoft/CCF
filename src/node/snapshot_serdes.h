// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose.h"
#include "ccf/crypto/cose_verifier.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/cose.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"
#include "node/cose_common.h"
#include "node/history.h"
#include "node/tx_receipt_impl.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct StartupSnapshotInfo
  {
    ccf::kv::Version seqno;
    std::vector<uint8_t> raw;

    StartupSnapshotInfo(ccf::kv::Version s, std::vector<uint8_t>&& r) :
      seqno(s),
      raw(std::move(r))
    {}
  };

  struct SnapshotSegments
  {
    std::span<const uint8_t> header_and_body;
    std::span<const uint8_t> receipt;
  };

  static SnapshotSegments separate_segments(
    const std::vector<uint8_t>& snapshot)
  {
    const auto* data = snapshot.data();
    auto size = snapshot.size();

    auto tx_hdr = serialized::peek<ccf::kv::SerialisedEntryHeader>(data, size);
    auto store_snapshot_size =
      sizeof(ccf::kv::SerialisedEntryHeader) + tx_hdr.size;

    if (tx_hdr.size == 0)
    {
      throw std::logic_error("Snapshot transaction size should not be zero");
    }

    const auto* receipt_data = data + store_snapshot_size;
    auto receipt_size = size - store_snapshot_size;

    if (receipt_size == 0)
    {
      throw std::logic_error("No receipt included in snapshot");
    }

    std::span<const uint8_t> header_and_body{data, store_snapshot_size};
    std::span<const uint8_t> receipt{receipt_data, receipt_size};

    return SnapshotSegments{header_and_body, receipt};
  }

  static void verify_cose_snapshot_receipt(
    const SnapshotSegments& segments,
    const std::optional<std::vector<uint8_t>>& prev_service_identity)
  {
    auto receipt = ccf::cose::decode_ccf_receipt(
      {segments.receipt.begin(), segments.receipt.end()},
      /* recompute_root */ true);

    auto snapshot_digest = ccf::crypto::Sha256Hash(
      segments.header_and_body.data(), segments.header_and_body.size());
    if (
      receipt.claims_digest.size() != ccf::crypto::Sha256Hash::SIZE ||
      std::memcmp(
        snapshot_digest.h.data(),
        receipt.claims_digest.data(),
        ccf::crypto::Sha256Hash::SIZE) != 0)
    {
      throw std::logic_error(fmt::format(
        "Snapshot digest ({}) does not match receipt claim ({})",
        snapshot_digest,
        ds::to_hex(receipt.claims_digest)));
    }

    if (prev_service_identity)
    {
      auto verifier =
        ccf::crypto::make_cose_verifier_from_cert(*prev_service_identity);
      if (!verifier->verify_detached(segments.receipt, receipt.merkle_root))
      {
        throw std::logic_error(
          "Previous service identity does not match the service identity that "
          "signed the snapshot");
      }
      LOG_DEBUG_FMT("Previous service identity matches snapshot signer");
    }
  }

  static void verify_json_snapshot_receipt(
    const SnapshotSegments& segments,
    const std::optional<std::vector<uint8_t>>& prev_service_identity)
  {
    auto j =
      nlohmann::json::parse(segments.receipt.begin(), segments.receipt.end());
    auto receipt_p = j.get<ReceiptPtr>();
    auto receipt = std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt_p);
    if (receipt == nullptr)
    {
      throw std::logic_error(
        "Unexpected receipt type: missing expanded claims");
    }

    auto snapshot_digest = ccf::crypto::Sha256Hash(
      segments.header_and_body.data(), segments.header_and_body.size());
    auto snapshot_digest_claim = receipt->leaf_components.claims_digest.value();
    if (snapshot_digest != snapshot_digest_claim)
    {
      throw std::logic_error(fmt::format(
        "Snapshot digest ({}) does not match receipt claim ({})",
        snapshot_digest,
        snapshot_digest_claim));
    }

    auto root = receipt->calculate_root();

    auto v = ccf::crypto::make_unique_verifier(receipt->cert);
    if (!v->verify_hash(
          root.h.data(),
          root.h.size(),
          receipt->signature.data(),
          receipt->signature.size(),
          ccf::crypto::MDType::SHA256))
    {
      throw std::logic_error(
        "Signature verification failed for snapshot receipt");
    }

    if (prev_service_identity)
    {
      ccf::crypto::Pem prev_pem(*prev_service_identity);
      if (!v->verify_certificate(
            {&prev_pem}, {}, true /* ignore_time */
            ))
      {
        throw std::logic_error(
          "Previous service identity does not endorse the node identity "
          "that signed the snapshot");
      }
      LOG_DEBUG_FMT("Previous service identity endorses snapshot signer");
    }
  }

  static void verify_snapshot(
    const SnapshotSegments& segments,
    std::optional<std::vector<uint8_t>> prev_service_identity = std::nullopt)
  {
    LOG_INFO_FMT(
      "Deserialising snapshot receipt (size: {}).", segments.receipt.size());
    constexpr size_t max_printed_size = 1024;
    if (segments.receipt.size() > max_printed_size)
    {
      LOG_INFO_FMT(
        "Receipt size ({}) exceeds max printed size ({}), only printing "
        "first {} bytes",
        segments.receipt.size(),
        max_printed_size,
        max_printed_size);
    }
    auto printed_size =
      std::min<size_t>(segments.receipt.size(), max_printed_size);
    LOG_INFO_FMT(
      "{}",
      ds::to_hex(
        segments.receipt.data(), segments.receipt.data() + printed_size));

    if (segments.receipt.empty())
    {
      throw std::logic_error("Empty snapshot receipt");
    }

    auto first_byte = segments.receipt[0];
    constexpr uint8_t ENCODED_COSE_SIGN1_TAG = 0xD2;
    if (first_byte == ENCODED_COSE_SIGN1_TAG)
    {
      LOG_DEBUG_FMT("Snapshot with COSE receipt detected");
      verify_cose_snapshot_receipt(segments, prev_service_identity);
    }
    else if (first_byte == '{')
    {
      LOG_DEBUG_FMT("Snapshot with JSON receipt detected");
      verify_json_snapshot_receipt(segments, prev_service_identity);
    }
    else
    {
      throw std::logic_error(fmt::format(
        "Invalid snapshot receipt: unrecognised format (first byte: 0x{:02X})",
        first_byte));
    }
  }

  static void deserialise_snapshot(
    const std::shared_ptr<ccf::kv::Store>& store,
    const SnapshotSegments& segments,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false)
  {
    const auto* data = segments.header_and_body.data();
    const auto size = segments.header_and_body.size();

    // Log full size as this snapshot appears in file, but after that ignore the
    // receipt segment
    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: {})",
      size + segments.receipt.size(),
      public_only);

    auto rc =
      store->deserialise_snapshot(data, size, hooks, view_history, public_only);
    if (rc != ccf::kv::ApplyResult::PASS)
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());
  };

  static void deserialise_snapshot(
    const std::shared_ptr<ccf::kv::Store>& store,
    const std::vector<uint8_t>& snapshot,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false)
  {
    const auto segments = separate_segments(snapshot);
    deserialise_snapshot(store, segments, hooks, view_history, public_only);
  }

  static std::vector<uint8_t> build_and_serialise_receipt(
    const std::vector<uint8_t>& cose_sig,
    const std::vector<uint8_t>& tree,
    ccf::kv::Version seqno,
    const ccf::crypto::Sha256Hash& write_set_digest,
    const std::string& commit_evidence,
    ccf::crypto::Sha256Hash&& claims_digest)
  {
    ccf::MerkleTreeHistory history(tree);
    auto proof = history.get_proof(seqno);
    ccf::ClaimsDigest cd;
    // NOLINTNEXTLINE(performance-move-const-arg)
    cd.set(std::move(claims_digest));
    ccf::TxReceiptImpl tx_receipt(
      {},
      cose_sig,
      proof.get_root(),
      proof.get_path(),
      {},
      std::nullopt,
      write_set_digest,
      commit_evidence,
      cd);

    // To be replaced with 'describe_cose_receipt' once 7700 is merged.
    auto cose_signature = ccf::describe_cose_signature_v1(tx_receipt);
    if (!cose_signature.has_value())
    {
      throw std::logic_error(
        "No COSE signature available for snapshot receipt");
    }
    auto merkle_proof = ccf::describe_merkle_proof_v1(tx_receipt);
    if (!merkle_proof.has_value())
    {
      return *cose_signature;
    }

    ccf::cose::edit::desc::Value desc{
      ccf::cose::edit::pos::AtKey{ccf::cose::header::iana::INCLUSION_PROOFS},
      ccf::cose::header::iana::VDP,
      *merkle_proof};
    return ccf::cose::edit::set_unprotected_header(*cose_signature, desc);
  }
}
