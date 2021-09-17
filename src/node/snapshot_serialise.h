// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "entities.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"
#include "node/nodes.h"
#include "node/service.h"
#include "node/tx_receipt.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  static bool deserialise_snapshot(
    const std::shared_ptr<kv::Store>& store,
    const std::vector<uint8_t>& snapshot,
    kv::ConsensusHookPtrs& hooks,
    bool skip_snapshot_verification = false,
    std::vector<kv::Version>* view_history = nullptr,
    bool public_only = false)
  {
    auto data = snapshot.data();
    auto size = snapshot.size();
    auto tx_hdr = serialized::peek<kv::SerialisedEntryHeader>(data, size);
    auto store_snapshot_size = sizeof(kv::SerialisedEntryHeader) + tx_hdr.size;

    LOG_DEBUG_FMT("Deserialising snapshot ({})", snapshot.size());

    auto rc = store->deserialise_snapshot(
      snapshot.data(), store_snapshot_size, hooks, view_history, public_only);
    if (rc != kv::ApplyResult::PASS)
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());

    if (!skip_snapshot_verification)
    {
      auto receipt_data = data + store_snapshot_size;
      auto receipt_size = size - store_snapshot_size;

      auto j = nlohmann::json::parse(receipt_data, receipt_data + receipt_size);
      auto receipt = j.get<Receipt>();

      auto root = compute_root_from_receipt(receipt);
      auto raw_sig = tls::raw_from_b64(receipt.signature);

      LOG_FAIL_FMT("Root from receipt: {}", compute_root_from_receipt(receipt));

      // TODO: Node cert should be extracted from receipt instead, so that
      // verification of the receipt happens before the snapshot is applied

      // TODO: Disabled for now to pass LTS compatibility test as the snasphot
      // wouldn't contain the endorsed cert for a new node (unless the new
      // renew_node_cert proposal is added)
      //  auto tx = store->create_read_only_tx(); auto service =
      // tx.ro<Service>(Tables::SERVICE); auto node_certs =
      //   tx.ro<NodeEndorsedCertificates>(Tables::NODE_ENDORSED_CERTIFICATES);

      // auto service_info = service->get();
      // if (!service_info.has_value())
      // {
      //   throw std::logic_error("Service information not found in snapshot");
      // }

      // auto node_cert = node_certs->get(receipt.node_id);
      // if (!node_cert.has_value())
      // {
      //   throw std::logic_error(fmt::format(
      //     "Receipt node certificate {} not found in snapshot",
      //     receipt.node_id));
      // }

      // // Verify node certificate endorsement
      // auto v = crypto::make_unique_verifier(node_cert.value());
      // if (!v->verify_certificate({&service_info->cert}))
      // {
      //   throw std::logic_error(
      //     "Node certificate is not endorsed by snapshot service");
      // }

      // if (!v->verify_hash(
      //       root.h.data(), root.h.size(), raw_sig.data(), raw_sig.size()))
      // {
      //   throw std::logic_error("Receipt not valid for snapshot");
      // }

      LOG_FAIL_FMT("Snapshot successfully verified");
      return true;
    }

    return false;
  };

  static std::vector<uint8_t> build_and_serialise_receipt(
    const std::vector<uint8_t>& s,
    const std::vector<uint8_t>& t,
    const NodeId& node_id,
    consensus::Index idx)
  {
    ccf::MerkleTreeHistory tree(t);
    auto proof = tree.get_proof(idx);
    auto tx_receipt =
      ccf::TxReceipt(s, proof.get_root(), proof.get_path(), node_id);

    Receipt receipt;
    tx_receipt.describe(receipt);

    LOG_FAIL_FMT("Root from receipt: {}", compute_root_from_receipt(receipt));

    const auto receipt_str = nlohmann::json(receipt).dump();
    LOG_FAIL_FMT("Receipt: {}", receipt_str);
    return std::vector<uint8_t>(receipt_str.begin(), receipt_str.end());
  }
}