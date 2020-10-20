// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/tx.h"

#include <doctest/doctest.h>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
};

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>("public:string_map");
  auto& num_map = store.create<MapTypes::NumNum>("public:num_map");

  kv::Version first_snapshot_version = kv::NoVersion;
  kv::Version second_snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "bar");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    first_snapshot_version = tx1.commit_version();

    auto tx2 = store.create_tx();
    auto view_2 = tx2.get_view(num_map);
    view_2->put(42, 123);
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);
    second_snapshot_version = tx2.commit_version();

    auto tx3 = store.create_tx();
    auto view_3 = tx1.get_view(string_map);
    view_3->put("key", "not committed");
    // Do not commit tx3
  }

  auto first_snapshot = store.snapshot(first_snapshot_version);
  auto first_serialised_snapshot =
    store.serialise_snapshot(std::move(first_snapshot));

  INFO("Apply snapshot at 1 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    REQUIRE_EQ(
      new_store.deserialise_snapshot(first_serialised_snapshot),
      kv::DeserialiseSuccess::PASS);
    REQUIRE_EQ(new_store.current_version(), 1);

    auto new_string_map =
      new_store.get<MapTypes::StringString>("public:string_map");
    auto new_num_map = new_store.get<MapTypes::NumNum>("public:num_map");

    REQUIRE(new_string_map != nullptr);
    REQUIRE(new_num_map != nullptr);

    auto tx1 = new_store.create_tx();
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

  auto second_snapshot = store.snapshot(second_snapshot_version);
  auto second_serialised_snapshot =
    store.serialise_snapshot(std::move(second_snapshot));

  INFO("Apply snapshot at 2 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map =
      new_store.get<MapTypes::StringString>("public:string_map");
    auto new_num_map = new_store.get<MapTypes::NumNum>("public:num_map");

    REQUIRE(new_string_map != nullptr);
    REQUIRE(new_num_map != nullptr);

    new_store.deserialise_snapshot(second_serialised_snapshot);
    REQUIRE_EQ(new_store.current_version(), 2);

    auto tx1 = new_store.create_tx();
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
  auto& string_map = store.create<MapTypes::StringString>("public:string_map");

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "foo");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK); // Committed at 1

    auto tx2 = store.create_tx();
    auto view_2 = tx2.get_view(string_map);
    view_2->put("bar", "bar");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot while committing a transaction");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map =
      new_store.get<MapTypes::StringString>("public:string_map");
    REQUIRE(new_string_map != nullptr);
    auto tx = new_store.create_tx();
    auto view = tx.get_view(*new_string_map);
    view->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    new_store.deserialise_snapshot(serialised_snapshot);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == kv::CommitSuccess::CONFLICT);

    view = tx.get_view(*new_string_map);
    view->put("baz", "baz");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }
}

TEST_CASE("Commit hooks with snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>("public:string_map");

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "foo");
    view_1->put("bar", "bar");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK); // Committed at 1

    // New transaction, deleting content from the previous transaction
    auto tx2 = store.create_tx();
    auto view_2 = tx2.get_view(string_map);
    view_2->put("baz", "baz");
    view_2->remove("bar");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot with local hook on target store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map =
      new_store.get<MapTypes::StringString>("public:string_map");
    REQUIRE(new_string_map != nullptr);

    using Write = MapTypes::StringString::Write;
    std::vector<Write> local_writes;
    std::vector<Write> global_writes;

    INFO("Set hooks on target store");
    {
      auto local_hook = [&](kv::Version v, const Write& w) {
        local_writes.push_back(w);
      };
      auto global_hook = [&](kv::Version v, const Write& w) {
        global_writes.push_back(w);
      };
      new_string_map->set_local_hook(local_hook);
      new_string_map->set_global_hook(global_hook);
    }

    new_store.deserialise_snapshot(serialised_snapshot);

    INFO("Verify content of snapshot");
    {
      auto tx = new_store.create_tx();
      auto view = tx.get_view(*new_string_map);
      REQUIRE(view->get("foo").has_value());
      REQUIRE(!view->get("bar").has_value());
      REQUIRE(view->get("baz").has_value());
    }

    INFO("Verify local hook execution");
    {
      REQUIRE_EQ(local_writes.size(), 1);
      auto writes = local_writes.at(0);
      REQUIRE_EQ(writes.at("foo"), "foo");
      REQUIRE_EQ(writes.find("bar"), writes.end());
      REQUIRE_EQ(writes.at("baz"), "baz");
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      REQUIRE_EQ(global_writes.size(), 1);
      auto writes = global_writes.at(0);
      REQUIRE_EQ(writes.at("foo"), "foo");
      REQUIRE_EQ(writes.find("bar"), writes.end());
      REQUIRE_EQ(writes.at("baz"), "baz");
    }
  }
}

TEST_CASE("Snapshot size" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& map = store.create<kv::Map<size_t, uint8_t>>("public:map");

  const auto empty_snapshot =
    store.serialise_snapshot(store.snapshot(store.current_version()));

  constexpr auto initial_key_count = 100;

  {
    INFO("Building initial state");
    auto tx = store.create_tx();
    auto view = tx.get_view(map);

    for (size_t i = 0; i < initial_key_count; ++i)
    {
      view->put(i, 0);
    }

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  const auto initial_snapshot =
    store.serialise_snapshot(store.snapshot(store.current_version()));

  SUBCASE("Adding keys increases snapshot size")
  {
    auto tx = store.create_tx();
    auto view = tx.get_view(map);

    for (size_t i = initial_key_count; i < 2 * initial_key_count; ++i)
    {
      view->put(i, 0);
    }

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto grown_snapshot =
      store.serialise_snapshot(store.snapshot(store.current_version()));

    REQUIRE(grown_snapshot.size() > initial_snapshot.size());
  }

  SUBCASE("Modifying values (of same size) does not affect snapshot size")
  {
    auto tx = store.create_tx();
    auto view = tx.get_view(map);

    for (size_t i = 0; i < initial_key_count; ++i)
    {
      const auto it = view->get(i);
      REQUIRE(it.has_value());
      view->put(i, it.value() + 1);
    }

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto modified_snapshot =
      store.serialise_snapshot(store.snapshot(store.current_version()));

    REQUIRE(modified_snapshot.size() == initial_snapshot.size());
  }

  SUBCASE("Deleting keys decreases snapshot size")
  {
    auto tx = store.create_tx();
    auto view = tx.get_view(map);

    for (size_t i = 0; i < initial_key_count / 2; ++i)
    {
      view->remove(i);
    }

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto shrunk_snapshot =
      store.serialise_snapshot(store.snapshot(store.current_version()));

    REQUIRE(shrunk_snapshot.size() < initial_snapshot.size());
  }

  SUBCASE("Removing every key produces an empty snapshot")
  {
    auto tx = store.create_tx();
    auto view = tx.get_view(map);

    view->foreach([&view](const auto& k, const auto&) {
      view->remove(k);
      return true;
    });

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto cleared_snapshot =
      store.serialise_snapshot(store.snapshot(store.current_version()));

    REQUIRE(cleared_snapshot.size() == empty_snapshot.size());
  }
}