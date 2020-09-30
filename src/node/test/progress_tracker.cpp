// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/progress_tracker.h"

#include "kv/store.h"
#include "node/nodes.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

TEST_CASE("Ordered Execution")
{
  kv::Store store;
  auto& nodes =
    store.create<ccf::Nodes>(ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& backup_signatures_map = store.create<ccf::BackupSignaturesMap>(
    ccf::Tables::BACKUP_SIGNATURES, kv::SecurityDomain::PUBLIC);
  auto& revealed_nonces_map = store.create<aft::RevealedNoncesMap>(
    ccf::Tables::NONCES, kv::SecurityDomain::PUBLIC);

  kv::Consensus::View view = 0;
  kv::Consensus::SeqNo seqno = 0;
  uint32_t node_count = 4;

  crypto::Sha256Hash root;
  std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN> sig;
  ccf::Nonce nonce;

  INFO("Adding signature");
  {
    auto pt = std::make_unique<ccf::ProgressTracker>(
      0, nodes, backup_signatures_map, revealed_nonces_map);
    auto result = pt->add_signature(
      view, seqno, 1, MBEDTLS_ECDSA_MAX_LEN, sig, nonce, node_count, true);
    REQUIRE(result == kv::TxHistory::Result::OK);
    REQUIRE_THROWS(pt->record_primary(view, seqno, 0, root, nonce, node_count));
  }

  INFO("Waits for signature tx");
  {
    auto pt = std::make_unique<ccf::ProgressTracker>(
      0, nodes, backup_signatures_map, revealed_nonces_map);
    for (size_t i = 0; i < node_count; ++i)
    {
      auto result = pt->add_signature_ack(view, seqno, i, node_count);
      REQUIRE(result == kv::TxHistory::Result::OK);
    }
  }
}
