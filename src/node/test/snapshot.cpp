// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/nodes.h"
#include "node/signatures.h"
#include "tls/key_pair.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

TEST_CASE("Snapshot with merkle tree" * doctest::test_suite("snapshot"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  kv::Store store(consensus);

  ccf::NodeId node_id = 0;
  auto node_kp = tls::make_key_pair();

  auto& signatures =
    store.create<ccf::Signatures>("ccf.signatures", kv::SecurityDomain::PUBLIC);
  auto& nodes =
    store.create<ccf::Nodes>("ccf.nodes", kv::SecurityDomain::PUBLIC);

  auto history = std::make_shared<ccf::MerkleTxHistory>(
    store, 0, *node_kp, signatures, nodes);

  store.set_history(history);

  auto& string_map = store.create<kv::Map<std::string, std::string>>(
    "string_map", kv::SecurityDomain::PUBLIC);

  size_t transactions_count = 1025;
  kv::Version snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    for (size_t i = 0; i < transactions_count; i++)
    {
      kv::Tx tx;
      auto view = tx.get_view(string_map);
      view->put(fmt::format("key#{}", i), "value");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }
  }

  auto serialised_tree_before_signature = history->get_tree().serialise();

  auto root_before_signature = history->get_replicated_state_root();
  LOG_DEBUG_FMT("Root before signature is: {}", root_before_signature);

  INFO("Apply signature");
  {
    LOG_DEBUG_FMT("\n\n Apply signature");
    history->emit_signature();
    snapshot_version = transactions_count + 1;

    LOG_DEBUG_FMT(
      "Root after signature: {}", history->get_replicated_state_root());
  }

  INFO("Check tree serialisation/deserialisation");
  {
    // First tree
    auto serialised_signature = consensus->get_latest_data().value();
    auto serialised_signature_hash = crypto::Sha256Hash(serialised_signature);

    LOG_DEBUG_FMT("Serialised signature hash: {}", serialised_signature_hash);

    LOG_DEBUG_FMT("\n\n\n");

    // Second tree
    ccf::MerkleTreeHistory target_history(serialised_tree_before_signature);

    LOG_DEBUG_FMT(
      "Target root before signature is: {}", target_history.get_root());

    target_history.append(serialised_signature_hash);

    LOG_DEBUG_FMT(
      "Target root after signature is: {}", target_history.get_root());

    REQUIRE(target_history.get_root() == history->get_replicated_state_root());
  }

  INFO("Snapshot at signature");
  {
    LOG_DEBUG_FMT("\n\n\n\nSnapshot!!: {}", transactions_count);
    auto snapshot = store.serialise_snapshot(snapshot_version);

    kv::Store new_store;
    auto new_node_kp = tls::make_key_pair();

    new_store.clone_schema(store);

    auto new_signatures = new_store.get<ccf::Signatures>("ccf.signatures");
    auto new_nodes = new_store.get<ccf::Nodes>("ccf.nodes");

    auto new_history = std::make_shared<ccf::MerkleTxHistory>(
      new_store, 0, *new_node_kp, *new_signatures, *new_nodes);

    new_store.set_history(new_history);

    new_store.deserialise_snapshot(snapshot);

    LOG_DEBUG_FMT(
      "Root after snapshot is: {}", new_history->get_replicated_state_root());

    REQUIRE(
      history->get_replicated_state_root() ==
      new_history->get_replicated_state_root());
  }
}
