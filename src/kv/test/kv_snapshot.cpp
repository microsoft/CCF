// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/tx.h"

// TODO: Remove
#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/nodes.h"
#include "node/signatures.h"
#include "tls/key_pair.h"

#include <doctest/doctest.h>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
};

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);
  auto& num_map =
    store.create<MapTypes::NumNum>("num_map", kv::SecurityDomain::PUBLIC);

  kv::Version first_snapshot_version = kv::NoVersion;
  kv::Version second_snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    kv::Tx tx1;
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "bar");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    first_snapshot_version = tx1.commit_version();

    kv::Tx tx2;
    auto view_2 = tx2.get_view(num_map);
    view_2->put(42, 123);
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);
    second_snapshot_version = tx2.commit_version();

    kv::Tx tx3;
    auto view_3 = tx1.get_view(string_map);
    view_3->put("key", "not committed");
    // Do not commit tx3
  }

  auto first_snapshot = store.serialise_snapshot(first_snapshot_version);

  INFO("Apply snapshot at 1 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    REQUIRE_EQ(
      new_store.deserialise_snapshot(first_snapshot),
      kv::DeserialiseSuccess::PASS);
    REQUIRE_EQ(new_store.current_version(), 1);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    auto new_num_map = new_store.get<MapTypes::NumNum>("num_map");

    kv::Tx tx1;
    auto view = tx1.get_view(*new_string_map);
    auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE_EQ(v.value(), "bar");

    auto view_ = tx1.get_view(*new_num_map);
    auto v_ = view_->get(42);
    REQUIRE(!v_.has_value());

    view = tx1.get_view(*new_string_map);
    v = view->get("key");
    REQUIRE(!v.has_value());
  }

  auto second_snapshot = store.serialise_snapshot(second_snapshot_version);
  INFO("Apply snapshot at 2 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);
    new_store.deserialise_snapshot(second_snapshot);
    REQUIRE_EQ(new_store.current_version(), 2);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    auto new_num_map = new_store.get<MapTypes::NumNum>("num_map");

    kv::Tx tx1;
    auto view = tx1.get_view(*new_string_map);

    auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE_EQ(v.value(), "bar");

    auto view_ = tx1.get_view(*new_num_map);
    auto v_ = view_->get(42);
    REQUIRE(v_.has_value());
    REQUIRE_EQ(v_.value(), 123);

    view = tx1.get_view(*new_string_map);
    v = view->get("key");
    REQUIRE(!v.has_value());
  }
}

TEST_CASE(
  "Commit transaction while applying snapshot" *
  doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    kv::Tx tx1;
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "foo");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK); // Committed at 1

    kv::Tx tx2;
    auto view_2 = tx2.get_view(string_map);
    view_2->put("bar", "bar");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.serialise_snapshot(snapshot_version);

  INFO("Apply snapshot while committing a transaction");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    kv::Tx tx;
    auto view = tx.get_view(*new_string_map);
    view->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    new_store.deserialise_snapshot(snapshot);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == kv::CommitSuccess::CONFLICT);

    view = tx.get_view(*new_string_map);
    view->put("baz", "baz");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }
}

// TODO: Move outside of KV test
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

  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);

  kv::Version snapshot_version = kv::NoVersion;
  size_t transactions_count = 10;

  for (size_t n = 0; n < transactions_count; n++)
  {
    INFO("Apply transactions to original store");
    {
      for (size_t i = 0; i < n; i++)
      {
        kv::Tx tx;
        auto view = tx.get_view(string_map);
        view->put(fmt::format("key#{}", i), "value");
        REQUIRE(tx.commit() == kv::CommitSuccess::OK);
      }
    }

    auto& original_tree = history->get_tree();
    auto serialised_tree_before_signature = original_tree.serialise();
    auto root_before_signature = original_tree.get_root();
    LOG_DEBUG_FMT("Root before signature is: {}", root_before_signature);

    INFO("Apply signature");
    {
      history->emit_signature();
    }

    // First tree
    auto serialised_signature = consensus->get_latest_data().value();
    auto serialised_signature_hash = crypto::Sha256Hash(serialised_signature);

    LOG_DEBUG_FMT("Serialised signature hash: {}", serialised_signature_hash);

    LOG_DEBUG_FMT("Root after signature is: {}", original_tree.get_root());

    LOG_DEBUG_FMT("\n\n\n");

    // Second tree
    ccf::MerkleTreeHistory target_history(serialised_tree_before_signature);

    LOG_DEBUG_FMT(
      "Target root before signature is: {}", target_history.get_root());

    target_history.append(serialised_signature_hash);

    LOG_DEBUG_FMT(
      "Target root after signature is: {}", target_history.get_root());

    for (size_t i = target_history.begin_index();
         i <= target_history.end_index();
         ++i)
    {
      LOG_DEBUG_FMT("One leaf: {}", i);
      REQUIRE(target_history.get_leaf(i) == original_tree.get_leaf(i));
    }

    LOG_DEBUG_FMT("Transactions count: {}", n);
    REQUIRE(target_history.get_root() == original_tree.get_root());
  }
}