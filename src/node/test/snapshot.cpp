// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/key_pair.h"
#include "ccf/service/tables/nodes.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL
#include <string>

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

TEST_CASE("Snapshot with merkle tree" * doctest::test_suite("snapshot"))
{
  auto source_consensus = std::make_shared<kv::test::StubConsensus>();
  kv::Store source_store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  source_store.set_encryptor(encryptor);
  source_store.set_consensus(source_consensus);

  ccf::NodeId source_node_id = kv::test::PrimaryNodeId;
  auto source_node_kp = crypto::make_key_pair();

  auto source_history = std::make_shared<ccf::MerkleTxHistory>(
    source_store, source_node_id, *source_node_kp);
  source_history->set_endorsed_certificate({});

  source_store.set_history(source_history);

  kv::Map<std::string, std::string> string_map("public:string_map");

  size_t transactions_count = 3;
  kv::Version snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    for (size_t i = 0; i < transactions_count; i++)
    {
      auto tx = source_store.create_tx();
      auto map = tx.rw(string_map);
      map->put(fmt::format("key#{}", i), "value");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }
  }

  auto source_root_before_signature =
    source_history->get_replicated_state_root();

  INFO("Emit signature");
  {
    source_history->emit_signature();
    // Snapshot version is the version of the signature
    snapshot_version = transactions_count + 1;
  }

  INFO("Check tree start from mini-tree and sig hash");
  {
    // No snapshot here, only verify that a fresh tree can be started from the
    // mini-tree in a signature and the hash of the signature
    auto tx = source_store.create_read_only_tx();
    auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
    REQUIRE(signatures->has());
    auto sig = signatures->get().value();
    auto serialised_tree =
      tx.ro<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE);
    REQUIRE(serialised_tree->has());
    auto tree = serialised_tree->get();

    auto serialised_signature = source_consensus->get_latest_data().value();

    ccf::MerkleTreeHistory target_tree(tree.value());
    REQUIRE(source_root_before_signature == target_tree.get_root());

    target_tree.append(ccf::entry_leaf(
      serialised_signature,
      crypto::Sha256Hash("ce:0.4:"),
      ccf::empty_claims()));
    REQUIRE(
      target_tree.get_root() == source_history->get_replicated_state_root());
  }

  INFO("Snapshot at signature");
  {
    kv::Store target_store;
    auto encryptor = std::make_shared<kv::NullTxEncryptor>();
    target_store.set_encryptor(encryptor);
    INFO("Setup target store");
    {
      auto target_node_kp = crypto::make_key_pair();

      auto target_history = std::make_shared<ccf::MerkleTxHistory>(
        target_store, kv::test::PrimaryNodeId, *target_node_kp);
      target_history->set_endorsed_certificate({});
      target_store.set_history(target_history);
    }

    auto target_history = target_store.get_history();

    INFO("Apply snapshot taken before any signature was emitted");
    {
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
      {
        kv::ScopedStoreMapsLock maps_lock(&source_store);
        snapshot = source_store.snapshot_unsafe_maps(snapshot_version - 1);
      }
      auto serialised_snapshot =
        source_store.serialise_snapshot(std::move(snapshot));

      // There is no signature to read to seed the target history
      std::vector<kv::Version> view_history;
      kv::ConsensusHookPtrs hooks;
      REQUIRE(
        target_store.deserialise_snapshot(
          serialised_snapshot.data(),
          serialised_snapshot.size(),
          hooks,
          &view_history) == kv::ApplyResult::FAIL);
    }

    INFO("Apply snapshot taken at signature");
    {
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
      {
        kv::ScopedStoreMapsLock maps_lock(&source_store);
        snapshot = source_store.snapshot_unsafe_maps(snapshot_version);
      }
      auto serialised_snapshot =
        source_store.serialise_snapshot(std::move(snapshot));

      std::vector<kv::Version> view_history;
      kv::ConsensusHookPtrs hooks;
      REQUIRE(
        target_store.deserialise_snapshot(
          serialised_snapshot.data(),
          serialised_snapshot.size(),
          hooks,
          &view_history) == kv::ApplyResult::PASS);

      // Merkle history and view history thus far are restored when applying
      // snapshot
      REQUIRE(
        source_history->get_replicated_state_root() ==
        target_history->get_replicated_state_root());
      REQUIRE(
        source_consensus->view_history.get_history_until() == view_history);
    }

    INFO("Deserialise additional transaction after restart");
    {
      auto tx = source_store.create_tx();
      auto map = tx.rw(string_map);
      map->put("key", "value");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

      auto serialised_tx = source_consensus->get_latest_data().value();

      target_store.deserialize(serialised_tx, ConsensusType::CFT)->apply();

      REQUIRE(
        target_history->get_replicated_state_root() ==
        source_history->get_replicated_state_root());
    }
  }
}

int main(int argc, char** argv)
{
  threading::ThreadMessaging::init(1);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
