// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/serialized.h"
#include "entities.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"
#include "node/nodes.h"
#include "node/service.h"
#include "node/tx_receipt.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct StartupSnapshotInfo
  {
    std::vector<uint8_t> raw;
    kv::Version seqno;
    std::optional<kv::Version> evidence_seqno = std::nullopt;

    // Store used to verify a snapshot (either created fresh when a node joins
    // from a snapshot or points to the main store when recovering from a
    // snapshot)
    std::shared_ptr<kv::Store> store = nullptr;

    // The snapshot to startup from (on join or recovery) is only valid once a
    // signature ledger entry confirms that the snapshot evidence was
    // committed
    bool has_evidence = false;
    bool is_evidence_committed = false;

    StartupSnapshotInfo(
      const std::shared_ptr<kv::Store>& store_,
      std::vector<uint8_t>&& raw_,
      kv::Version seqno_,
      std::optional<kv::Version> evidence_seqno_) :
      raw(std::move(raw_)),
      seqno(seqno_),
      evidence_seqno(evidence_seqno_),
      store(store_)
    {}

    bool is_snapshot_verified() const
    {
      return has_evidence && is_evidence_committed;
    }

    bool requires_ledger_verification() const
    {
      // Snapshot evidence seqno is only set by the host for 1.x snapshots
      // whose evidence need to be verified in the ledger suffix on startup
      return evidence_seqno.has_value();
    }
  };

  static void deserialise_snapshot(
    const std::shared_ptr<kv::Store>& store,
    const std::vector<uint8_t>& snapshot,
    kv::ConsensusHookPtrs& hooks,
    std::vector<kv::Version>* view_history = nullptr,
    bool public_only = false,
    std::optional<kv::Version> evidence_seqno = std::nullopt)
  {
    const auto* data = snapshot.data();
    auto size = snapshot.size();

    auto tx_hdr = serialized::peek<kv::SerialisedEntryHeader>(data, size);
    auto store_snapshot_size = sizeof(kv::SerialisedEntryHeader) + tx_hdr.size;

    // Snapshots without a snapshot evidence seqno specified by the host should
    // be self-verifiable with embedded receipt
    if (!evidence_seqno.has_value())
    {
      auto receipt_data = data + store_snapshot_size;
      auto receipt_size = size - store_snapshot_size;

      auto j = nlohmann::json::parse(receipt_data, receipt_data + receipt_size);
      auto receipt = j.get<Receipt>();

      auto root = compute_root_from_receipt(receipt);
      auto raw_sig = crypto::raw_from_b64(receipt.signature);
    }

    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: {})",
      snapshot.size(),
      public_only);

    auto rc = store->deserialise_snapshot(
      snapshot.data(), store_snapshot_size, hooks, view_history, public_only);
    if (rc != kv::ApplyResult::PASS)
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());

    // Snapshots without a snapshot evidence seqno specified by the host should
    // be self-verifiable with embedded receipt
    if (!evidence_seqno.has_value())
    {
      auto receipt_data = data + store_snapshot_size;
      auto receipt_size = size - store_snapshot_size;

      auto j = nlohmann::json::parse(receipt_data, receipt_data + receipt_size);
      auto receipt = j.get<Receipt>();

      auto root = compute_root_from_receipt(receipt);
      auto raw_sig = crypto::raw_from_b64(receipt.signature);

      if (!receipt.cert.has_value())
      {
        throw std::logic_error("Missing node certificate in snapshot receipt");
      }

      auto v = crypto::make_unique_verifier(receipt.cert.value());
      if (!v->verify_hash(
            root.h.data(), root.h.size(), raw_sig.data(), raw_sig.size()))
      {
        throw std::logic_error(
          "Signature verification failed for snapshot receipt");
      }
    }
  };

  static std::unique_ptr<StartupSnapshotInfo> initialise_from_snapshot(
    const std::shared_ptr<kv::Store>& store,
    std::vector<uint8_t>&& snapshot,
    kv::ConsensusHookPtrs& hooks,
    std::vector<kv::Version>* view_history = nullptr,
    bool public_only = false,
    std::optional<kv::Version> evidence_seqno = std::nullopt)
  {
    deserialise_snapshot(
      store, snapshot, hooks, view_history, public_only, evidence_seqno);
    return std::make_unique<StartupSnapshotInfo>(
      store, std::move(snapshot), store->current_version(), evidence_seqno);
  }

  static std::vector<uint8_t> build_and_serialise_receipt(
    const std::vector<uint8_t>& sig,
    const std::vector<uint8_t>& tree,
    const NodeId& node_id,
    const crypto::Pem& node_cert,
    kv::Version seqno)
  {
    ccf::MerkleTreeHistory history(tree);
    auto proof = history.get_proof(seqno);
    auto tx_receipt = ccf::TxReceipt(
      sig, proof.get_root(), proof.get_path(), node_id, node_cert);

    Receipt receipt;
    tx_receipt.describe(receipt);
    const auto receipt_str = nlohmann::json(receipt).dump();
    return std::vector<uint8_t>(receipt_str.begin(), receipt_str.end());
  }
}
