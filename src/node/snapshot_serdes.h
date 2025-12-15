// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_adapter.h"
#include "ccf/service/tables/nodes.h"
#include "ds/internal_logger.h"
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

  static void deserialise_snapshot(
    const std::shared_ptr<ccf::kv::Store>& store,
    const std::vector<uint8_t>& snapshot,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false,
    std::optional<std::vector<uint8_t>> prev_service_identity = std::nullopt)
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

    LOG_INFO_FMT("Deserialising snapshot receipt (size: {}).", receipt_size);
    constexpr size_t max_printed_size = 1024;
    if (receipt_size > max_printed_size)
    {
      LOG_INFO_FMT(
        "Receipt size ({}) exceeds max printed size ({}), only printing "
        "first {} bytes",
        receipt_size,
        max_printed_size,
        max_printed_size);
    }
    auto printed_size = std::min<size_t>(receipt_size, max_printed_size);
    LOG_INFO_FMT("{}", ds::to_hex(receipt_data, receipt_data + printed_size));

    auto j = nlohmann::json::parse(receipt_data, receipt_data + receipt_size);
    auto receipt_p = j.get<ReceiptPtr>();
    auto receipt = std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt_p);
    if (receipt == nullptr)
    {
      throw std::logic_error(
        fmt::format("Unexpected receipt type: missing expanded claims"));
    }

    auto snapshot_digest =
      ccf::crypto::Sha256Hash({snapshot.data(), store_snapshot_size});
    auto snapshot_digest_claim = receipt->leaf_components.claims_digest.value();
    if (snapshot_digest != snapshot_digest_claim)
    {
      throw std::logic_error(fmt::format(
        "Snapshot digest ({}) does not match receipt claim ({})",
        snapshot_digest,
        snapshot_digest_claim));
    }

    auto root = receipt->calculate_root();
    auto raw_sig = receipt->signature;

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

    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: {})",
      snapshot.size(),
      public_only);

    auto rc = store->deserialise_snapshot(
      snapshot.data(), store_snapshot_size, hooks, view_history, public_only);
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
    // NOLINTNEXTLINE(performance-move-const-arg)
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
    return {receipt_str.begin(), receipt_str.end()};
  }
}
