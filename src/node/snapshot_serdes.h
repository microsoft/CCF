// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/cose_receipt.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"
#include "node/history.h"
#include "node/tx_receipt_impl.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct StartupSnapshotInfo
  {
    std::vector<uint8_t> raw;
    ccf::kv::Version seqno;

    // Store used to verify a snapshot (either created fresh when a node joins
    // from a snapshot or points to the main store when recovering from a
    // snapshot)
    std::shared_ptr<ccf::kv::Store> store = nullptr;

    StartupSnapshotInfo(
      const std::shared_ptr<ccf::kv::Store>& store_,
      std::vector<uint8_t>&& raw_,
      ccf::kv::Version seqno_) :
      raw(std::move(raw_)),
      seqno(seqno_),
      store(store_)
    {}
  };

  struct SnapshotSegments
  {
    std::span<const uint8_t> header_and_body;
    std::span<const uint8_t> receipt;
  };

  static SnapshotSegments split_snapshot(const std::vector<uint8_t>& snapshot)
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

    auto receipt_data = data + store_snapshot_size;
    auto receipt_size = size - store_snapshot_size;

    if (receipt_size == 0)
    {
      throw std::logic_error("No receipt included in snapshot");
    }

    return SnapshotSegments{
      {data, store_snapshot_size}, {receipt_data, receipt_size}};
  }

  static void verify_cose_snapshot_receipt(
    const SnapshotSegments& segments,
    const std::optional<std::vector<uint8_t>>& prev_service_identity)
  {
    auto contents = ccf::cose::parse_cose_receipt(segments.receipt);
    LOG_DEBUG_FMT("COSE receipt KID (node ID): {}", contents.kid);

    if (contents.proofs.empty())
    {
      throw std::logic_error("No Merkle proofs found in COSE receipt");
    }

    auto snapshot_digest = ccf::crypto::Sha256Hash(
      {segments.header_and_body.data(), segments.header_and_body.size()});
    auto& claims_digest_bytes = contents.proofs[0].claims_digest;
    if (claims_digest_bytes.size() != ccf::crypto::Sha256Hash::SIZE)
    {
      throw std::logic_error(fmt::format(
        "Unsupported claims digest size: {}", claims_digest_bytes.size()));
    }
    ccf::crypto::Sha256Hash snapshot_digest_claim =
      ccf::crypto::Sha256Hash::from_span(
        std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE>{
          claims_digest_bytes.data(), ccf::crypto::Sha256Hash::SIZE});
    if (snapshot_digest != snapshot_digest_claim)
    {
      throw std::logic_error(fmt::format(
        "Snapshot digest ({}) does not match COSE receipt claim ({})",
        snapshot_digest,
        snapshot_digest_claim));
    }

    auto merkle_root = ccf::cose::verify_merkle_root(contents.proofs);
    LOG_DEBUG_FMT(
      "COSE snapshot receipt Merkle root verified for node {}", contents.kid);

    if (prev_service_identity)
    {
      ccf::cose::verify_kid_matches_service_identity(
        contents.kid, *prev_service_identity);
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
        fmt::format("Unexpected receipt type: missing expanded claims"));
    }

    auto snapshot_digest = ccf::crypto::Sha256Hash(
      {segments.header_and_body.data(), segments.header_and_body.size()});
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
            {&prev_pem},
            {}, /* ignore_time */
            true))
      {
        throw std::logic_error(
          "Previous service identity does not endorse the node identity that "
          "signed the snapshot");
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
    const std::vector<uint8_t>& snapshot,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false,
    std::optional<std::vector<uint8_t>> prev_service_identity = std::nullopt)
  {
    auto segments = split_snapshot(snapshot);

    verify_snapshot(segments, prev_service_identity);

    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: {})",
      snapshot.size(),
      public_only);

    auto rc = store->deserialise_snapshot(
      segments.header_and_body.data(),
      segments.header_and_body.size(),
      hooks,
      view_history,
      public_only);
    if (rc != ccf::kv::ApplyResult::PASS)
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());
  };

  static std::unique_ptr<StartupSnapshotInfo> initialise_from_snapshot(
    const std::shared_ptr<ccf::kv::Store>& store,
    std::vector<uint8_t>&& snapshot,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false,
    std::optional<std::vector<uint8_t>> previous_service_identity =
      std::nullopt)
  {
    deserialise_snapshot(
      store,
      snapshot,
      hooks,
      view_history,
      public_only,
      previous_service_identity);
    return std::make_unique<StartupSnapshotInfo>(
      store, std::move(snapshot), store->current_version());
  }

  static std::vector<uint8_t> build_and_serialise_receipt(
    const std::vector<uint8_t>& sig,
    const std::vector<uint8_t>& tree,
    const NodeId& node_id,
    const ccf::crypto::Pem& node_cert,
    ccf::kv::Version seqno,
    const ccf::crypto::Sha256Hash& write_set_digest,
    const std::string& commit_evidence,
    ccf::crypto::Sha256Hash&& claims_digest)
  {
    ccf::MerkleTreeHistory history(tree);
    auto proof = history.get_proof(seqno);
    ccf::ClaimsDigest cd;
    cd.set(std::move(claims_digest));
    ccf::TxReceiptImpl tx_receipt(
      sig,
      std::nullopt, // cose
      proof.get_root(),
      proof.get_path(),
      node_id,
      node_cert,
      write_set_digest,
      commit_evidence,
      cd);

    auto receipt = ccf::describe_receipt_v1(tx_receipt);
    const auto receipt_str = receipt.dump();
    return std::vector<uint8_t>(receipt_str.begin(), receipt_str.end());
  }
}
