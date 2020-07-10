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

  auto first_snapshot = store.snapshot(first_snapshot_version);

  INFO("Verify content of snapshot");
  {
    auto& vec_s = first_snapshot->get_map_snapshots();
    for (auto& s : vec_s)
    {
      REQUIRE_EQ(s->get_security_domain(), kv::SecurityDomain::PUBLIC);
      REQUIRE_EQ(s->get_is_replicated(), true);

      // Only string_map is committed at version 1
      if (s->get_name() == "string_map")
      {
        REQUIRE_GT(s->get_serialized_size(), 0);
      }
      else
      {
        REQUIRE_EQ(s->get_name(), "num_map");
        REQUIRE_EQ(s->get_serialized_size(), 0);
      }
    }
  }

  INFO("Apply snapshot at 1 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    new_store.deserialize(first_snapshot);
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

  auto second_snapshot = store.snapshot(second_snapshot_version);
  INFO("Apply snapshot at 2 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);
    new_store.deserialize(second_snapshot);
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

  auto snapshot = store.snapshot(snapshot_version);

  INFO("Apply snapshot while committing a transaction");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    kv::Tx tx;
    auto view = tx.get_view(*new_string_map);
    view->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    new_store.deserialize(snapshot);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == kv::CommitSuccess::CONFLICT);

    view = tx.get_view(*new_string_map);
    view->put("baz", "baz");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }
}

TEST_CASE("Serialised snapshot")
{
  LOG_DEBUG_FMT("Serialising snapshots!!");

  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);
  auto& num_map =
    store.create<MapTypes::NumNum>("num_map", kv::SecurityDomain::PRIVATE);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  kv::Tx tx1;
  auto view_1 = tx1.get_view(string_map);
  view_1->put("foo", "bar");
  REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

  kv::Tx tx2;
  auto view_2 = tx2.get_view(num_map);
  view_2->put(42, 123);
  REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

  auto snapshot_serial = store.snapshot_serialise(2);
  REQUIRE(snapshot_serial.size() == 0);
}